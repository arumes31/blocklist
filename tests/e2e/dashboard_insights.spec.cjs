const AxeBuilder = require('@axe-core/playwright').default;
const {test, expect, unique} = require('./fixtures.cjs');

const countries = ['US', 'GB', 'NL', 'DE', 'FR', 'CN', 'CA', 'PT', 'BE', 'BG'];
const reasons = [
  'ISDB-*-Scanner', 'Implicit Deny', 'ISDB-Malicious-Malicious.Server',
  'ISDB-Tor-Server', 'ISDB-Hosting-Bulletproof.Hosting', 'ZGrab.Scanner',
  'Nmap.Script.Scanner', 'MULTIPLE-SSL-LOGIN-FAILURES',
  'Apache.HTTP.Server.cgi-bin.Directory.Traversal.Attempt',
  'UnbrokenReason' + 'LongSegment'.repeat(8),
];

async function expectUnclipped(page) {
  const issues = await page.locator('.insight-chip').evaluateAll(chips => {
    const issues = [];
    for (const chip of chips) {
      const parent = chip.parentElement.getBoundingClientRect();
      const box = chip.getBoundingClientRect();
      if (box.left < parent.left - 1 || box.right > parent.right + 1) issues.push('Chip outside list: ' + chip.textContent);
      for (const el of [chip, ...chip.querySelectorAll('.insight-label, .insight-count')]) {
        if (el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1) {
          issues.push('Clipped contents: ' + el.textContent);
        }
        const child = el.getBoundingClientRect();
        if (child.left < box.left - 1 || child.right > box.right + 1 || child.bottom > box.bottom + 1) {
          issues.push('Contents outside chip: ' + el.textContent);
        }
      }
    }
    return issues;
  });
  expect(issues, 'Labels wrap and counts remain entirely inside their chips').toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2),
    'Insights do not widen the page').toBe(true);
}

async function chipContents(locator) {
  return locator.evaluateAll(chips => chips.map(chip => ({
    className: chip.className, title: chip.title,
    children: [...chip.children].map(child => ({className: child.className, text: child.textContent.trim()})),
  })).sort((a, b) => a.title.localeCompare(b.title)));
}

test('dashboard reason rankings filter real records exactly and survive refresh, reload and export', async ({page, api}, info) => {
  const subnet = info.project.name === 'mobile' ? '203.0.113' : '192.0.2';
  const ips = reasons.map((_, i) => `${subnet}.${220 + i}`);
  const prefix = unique('insights');
  const seededReasons = reasons.map(reason => `${prefix}-${reason}`);
  seededReasons[1] = `${seededReasons[0]}-extra`;
  try {
    for (const [i, ip] of ips.entries()) {
      const response = await api.post('/block', {data: {ip, reason: seededReasons[i], persist: true}});
      expect(response.ok(), await response.text()).toBeTruthy();
    }
    // Aggregates have a five-second cache; wait on the real state, not a sleep.
    await expect.poll(async () => {
      const response = await api.get('/api/v1/stats');
      expect(response.ok()).toBeTruthy();
      return (await response.json()).top_reasons.map(item => item.reason).sort();
    }).toEqual([...seededReasons].sort());
    await page.goto('/dashboard');
    await page.mouse.move(page.viewportSize().width - 4, 4);
    const chips = page.locator('#stat-reasons .insight-chip');
    await expect(chips).toHaveCount(10);
    const initial = await chipContents(chips);
    expect(initial.map(chip => chip.title).sort()).toEqual([...seededReasons].sort());
    await expectUnclipped(page);
    const exactReason = page.getByRole('button', {name: `Filter by reason ${seededReasons[0]}`, exact: true});
    await exactReason.locator('.insight-count').click();
    await expect(page.locator('#filterInput')).toHaveValue(`reason:${seededReasons[0]}`);
    await expect(page.locator('#ipTableBody .ip-details-link')).toHaveText([ips[0]]);
    await expect(exactReason).toHaveAttribute('aria-pressed', 'true');
    await exactReason.focus();
    // Wait for the initial health-only check before requesting full stats.
    await expect.poll(() => page.evaluate(() => statsLoading)).toBe(false);
    for (let refresh = 0; refresh < 2; refresh++) {
      await page.evaluate(() => refreshStats());
      await expect(chips).toHaveCount(10);
      expect(await chipContents(chips)).toEqual(initial);
      await expect(exactReason).toHaveAttribute('aria-pressed', 'true');
      await expect(exactReason).toBeFocused();
      await expectUnclipped(page);
    }
    await page.reload();
    await expect(exactReason).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('#ipTableBody .ip-details-link')).toHaveText([ips[0]]);
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', {name: 'JSON', exact: true}).click();
    const download = await downloadPromise;
    expect(await download.failure()).toBeNull();
    const chunks = [];
    for await (const chunk of await download.createReadStream()) chunks.push(chunk);
    const exported = Buffer.concat(chunks).toString('utf8');
    expect(exported).toContain(ips[0]);
    expect(exported).not.toContain(ips[1]);
    await exactReason.press('Space');
    await expect(exactReason).toHaveAttribute('aria-pressed', 'false');
    await expect(page.locator('#filterInput')).toHaveValue('');
    await expect(page.locator('#ipTableBody .ip-details-link')).toHaveCount(10);
    await exactReason.press('Enter');
    await expect(page.locator('#ipTableBody .ip-details-link')).toHaveText([ips[0]]);
    await page.locator('.remove-filter-chip[data-filter-key="query"]').click();
    await expect(exactReason).toHaveAttribute('aria-pressed', 'false');
    await expect(page.locator('#ipTableBody .ip-details-link')).toHaveCount(10);
  } finally {
    const response = await api.post('/bulk_unblock', {data: {ips}});
    expect(response.ok(), await response.text()).toBeTruthy();
  }
});

test('dashboard country and ASN filters remain interactive after scheduled refresh on every display', async ({page}, info) => {
  const now = new Date();
  await page.clock.install({time: now});
  await page.clock.pauseAt(new Date(now.getTime() + 1000));
  let revision = 0;
  let fail = false;
  let empty = false;
  await page.route('**/api/v1/stats', route => route.fulfill({
    status: fail ? 503 : 200,
    json: fail ? {error: 'Controlled stats failure'} : {
      top_countries: empty ? [] : countries.map((country, i) => ({country, count: 2300 - i + revision})),
      top_asns: empty ? [] : countries.map((_, i) => ({asn: 396982 + i, asn_org: `Network ${i}`, count: 422 - i + revision})),
      top_reasons: empty ? [] : reasons.map((reason, i) => ({reason, count: 1455 - i + revision})),
    },
  }));
  await page.goto('/dashboard?addedBy=operator&from=2026-01-01T00:00&to=2026-10-01T00:00');
  await page.mouse.move(page.viewportSize().width - 4, 4);
  await expect.poll(() => page.evaluate(() => statsLoading)).toBe(false);
  for (revision = 1; revision <= 3; revision++) {
    // Advance the actual 15-second interval instead of calling the renderer.
    await page.clock.fastForward(15000);
    await expect(page.locator('#stat-countries .insight-count').first()).toHaveText(String(2300 + revision));
    for (const id of ['stat-countries', 'stat-asns', 'stat-reasons']) {
      await expect(page.locator(`#${id} .insight-chip`)).toHaveCount(10);
    }
    await expect(page.locator('#stat-asns .insight-count').last()).toHaveText(String(413 + revision));
    await expect(page.locator('#stat-reasons .insight-count').last()).toHaveText(String(1446 + revision));
    await expectUnclipped(page);
  }
  const beforeFailure = await chipContents(page.locator('.insight-chip'));
  fail = true;
  await page.clock.fastForward(15000);
  await expect(page.locator('#health-dot')).toHaveAttribute('title', /Stats refresh failed/);
  expect(await chipContents(page.locator('.insight-chip'))).toEqual(beforeFailure);
  fail = false;
  empty = true;
  await page.clock.fastForward(15000);
  await expect(page.locator('.insight-chip')).toHaveCount(0);
  for (const id of ['stat-countries', 'stat-asns', 'stat-reasons']) {
    expect(await page.locator(`#${id}`).evaluate(el => getComputedStyle(el, '::after').content)).toContain('No activity recorded');
  }
  empty = false;
  await page.clock.fastForward(15000);
  await expect(page.locator('.insight-chip')).toHaveCount(30);
  const country = page.getByRole('button', {name: 'Filter by country US', exact: true});
  const asn = page.getByRole('button', {name: 'Filter by ASN 396982', exact: true});
  /**
   * Observe the matching IP-list response before triggering a filter interaction.
   * @param {() => Promise<unknown>} action Interaction or clock advance to perform.
   * @param {Object<string, string>} expected Required query values; absent means empty.
   * @returns {Promise<URLSearchParams>} Parameters of the successful response.
   */
  async function filterRequest(action, expected) {
    const response = page.waitForResponse(response => {
      const url = new URL(response.url());
      return url.pathname === '/api/v1/ips' && Object.entries(expected).every(([key, value]) =>
        (url.searchParams.get(key) || '') === value);
    });
    await action();
    const received = await response;
    expect(received.ok()).toBeTruthy();
    return new URL(received.url()).searchParams;
  }
  await filterRequest(() => country.locator('.flag-icon').click(), {country: 'US'});
  await expect(page.locator('#countryList input[value="US"]')).toBeChecked();
  await expect(country).toHaveAttribute('aria-pressed', 'true');
  const parameters = await filterRequest(() => asn.press('Enter'), {country: 'US', query: 'asn:396982'});
  expect(parameters.get('added_by')).toBe('operator');
  expect(parameters.get('from')).toBe('2026-01-01T00:00:00.000Z');
  expect(parameters.get('to')).toBe('2026-10-01T00:00:00.000Z');
  expect(parameters.get('cursor') || '').toBe('');
  await expect(asn).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#filterInput')).toHaveValue('asn:396982');
  await asn.focus();
  await page.clock.fastForward(15000);
  await expect.poll(() => page.evaluate(() => statsLoading)).toBe(false);
  await expect(asn).toBeFocused();
  await expect(asn).toHaveAttribute('aria-pressed', 'true');
  await expect(country).toHaveAttribute('aria-pressed', 'true');
  await page.locator('#filterInput').fill('ASN: 396982');
  await filterRequest(() => page.clock.fastForward(400), {country: 'US', query: 'ASN: 396982'});
  await expect(asn).toHaveAttribute('aria-pressed', 'true');
  await filterRequest(() => asn.press('Space'), {country: 'US', query: ''});
  await expect(page.locator('#filterInput')).toHaveValue('');
  await filterRequest(() => asn.press('Enter'), {country: 'US', query: 'asn:396982'});
  await filterRequest(() => country.click(), {country: '', query: 'asn:396982'});
  await expect(country).toHaveAttribute('aria-pressed', 'false');
  await filterRequest(() => page.locator('#clearFilter').click(), {country: '', query: '', added_by: '', from: '', to: ''});
  await expect(asn).toHaveAttribute('aria-pressed', 'false');
  await filterRequest(() => country.click(), {country: 'US'});
  await filterRequest(() => asn.click(), {country: 'US', query: 'asn:396982'});
  await page.clock.resume();
  await page.evaluate(() => document.fonts.ready);
  if (info.project.name === 'mobile') {
    expect(await page.locator('.insight-chip').evaluateAll(chips =>
      chips.every(chip => chip.getBoundingClientRect().height >= 44)), 'Mobile filter targets are at least 44px tall').toBe(true);
  }
  await page.locator('.insights').screenshot({path: info.outputPath('dashboard-insights.png'), animations: 'disabled'});
  if (info.project.name === 'desktop') {
    for (const width of [2560, 1024, 768, 601]) {
      await page.setViewportSize({width, height: 1000});
      await expectUnclipped(page);
    }
    await page.setViewportSize({width: 1440, height: 1000});
  }
  const result = await new AxeBuilder({page}).include('.insights').withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
  expect(result.violations, 'Populated rankings pass accessibility checks').toEqual([]);
});

test('dashboard insight refresh keeps keyboard focus in its list or returns it to search', async ({page}) => {
  const now = new Date();
  await page.clock.install({time: now});
  await page.clock.pauseAt(new Date(now.getTime() + 1000));
  const payload = {
    top_countries: [{country: 'US', count: 3}, {country: 'AT', count: 2}],
    top_asns: [{asn: 396982, count: 3}, {asn: 6393, count: 2}],
    top_reasons: [{reason: 'Kept', count: 3}, {reason: 'Removed', count: 2}],
  };
  let fail = false;
  await page.route('**/api/v1/stats', route => route.fulfill({
    status: fail ? 503 : 200, json: fail ? {error: 'Controlled failure'} : payload,
  }));
  await page.goto('/dashboard');
  await expect.poll(() => page.evaluate(() => statsLoading)).toBe(false);
  await page.evaluate(() => refreshStats());
  for (const [id, key] of [['stat-countries', 'top_countries'], ['stat-asns', 'top_asns'], ['stat-reasons', 'top_reasons']]) {
    const chips = page.locator(`#${id} .insight-chip`);
    await expect(chips).toHaveCount(2);
    await chips.last().focus();
    fail = true;
    await page.evaluate(() => refreshStats());
    await expect(chips.last()).toBeFocused();
    fail = false;
    const original = payload[key];
    delete payload[key];
    await page.evaluate(() => refreshStats());
    await expect(chips.last()).toBeFocused();
    payload[key] = original.slice(0, 1);
    await page.evaluate(() => refreshStats());
    await expect(chips).toHaveCount(1);
    await expect(chips.first()).toBeFocused();
    payload[key] = [];
    await page.evaluate(() => refreshStats());
    await expect(chips).toHaveCount(0);
    await expect(page.locator('#filterInput')).toBeFocused();
    payload[key] = original;
    await page.evaluate(() => refreshStats());
    await expect(chips).toHaveCount(2);
    await expect(page.locator('#filterInput')).toBeFocused();
  }
});
