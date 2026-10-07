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

test('dashboard server-rendered rankings retain all ten real reasons and identical styling after refresh', async ({page, api}, info) => {
  const subnet = info.project.name === 'mobile' ? '203.0.113' : '192.0.2';
  const ips = reasons.map((_, i) => `${subnet}.${220 + i}`);
  const prefix = unique('insights');
  const seededReasons = reasons.map(reason => `${prefix}-${reason}`);
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
    // Wait for the initial health-only check before requesting full stats.
    await expect.poll(() => page.evaluate(() => statsLoading)).toBe(false);
    for (let refresh = 0; refresh < 2; refresh++) {
      await page.evaluate(() => refreshStats());
      await expect(chips).toHaveCount(10);
      expect(await chipContents(chips)).toEqual(initial);
      await expectUnclipped(page);
    }
  } finally {
    const response = await api.post('/bulk_unblock', {data: {ips}});
    expect(response.ok(), await response.text()).toBeTruthy();
  }
});

test('dashboard scheduled refresh keeps all rankings readable on wide, narrow and mobile displays', async ({page}, info) => {
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
  await page.goto('/dashboard');
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
  await page.clock.resume();
  await page.evaluate(() => document.fonts.ready);
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
