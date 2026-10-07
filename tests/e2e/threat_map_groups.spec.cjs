const AxeBuilder = require('@axe-core/playwright').default;
const {test, expect} = require('./fixtures.cjs');

test('threat-map groups expose all co-located IPs at deep zoom without losing live updates', async ({page}, info) => {
  await page.emulateMedia({reducedMotion:'reduce'});
  // Synthetic response only: no records are written to the app database.
  const entries = Object.fromEntries(Array.from({length:29}, (_, i) => [`192.0.2.${i + 1}`, {
    reason:'Synthetic cluster fixture', added_by:'UI regression fixture',
    geolocation:{latitude:47, longitude:17, country:'Austria', city:'Synthetic Austrian group'},
  }]));
  entries['198.51.100.1'] = {reason:'Separate synthetic origin', geolocation:{latitude:30, longitude:150, country:'Japan'}};
  await page.route('**/api/v1/ips_list', route => route.fulfill({json:entries}));
  await page.route('**/api/v1/stats', route => route.fulfill({json:{active_blocks:Object.keys(entries).length,
    day:0, hour:0, whitelisted:0, blocks_minute:0,
    top_countries:[{country:'Austria', count:Object.keys(entries).length - 1}, {country:'Japan', count:1}],
  }}));
  await page.goto('/threat-map');
  await expect(page.locator('#coverage-status')).toContainText('30 loaded / 30 reported');
  await page.locator('#region').selectOption('europe');
  const canvas = page.locator('#scene');
  await canvas.scrollIntoViewIfNeeded();
  const clickCentre = async () => {
    const box = await canvas.boundingBox();
    await canvas.click({position:{x:box.width / 2, y:box.height / 2}});
  };
  await clickCentre();
  await expect(page.locator('#group-label')).toHaveText('29 IPs share this GeoIP location.');
  await expect(page.locator('#group-help')).toContainText('Zoom cannot separate identical coordinates');
  await expect(page.locator('#zoom-level')).toHaveText('2×');
  await expect(page.locator('#origin-page')).toHaveText('1 / 5');

  await canvas.hover();
  await page.mouse.wheel(0, -10000);
  await expect(page.locator('#zoom-level')).toHaveText('128×');
  await expect(page.getByRole('button', {name:'Zoom in', exact:true})).toBeDisabled();
  await clickCentre();
  await expect(page.locator('#group-label')).toContainText('29 IPs');
  await page.locator('#inspect-group').click();
  await expect(page.locator('.origin-row').first()).toBeFocused();
  const seen = [];
  for (let i = 0; i < 5; i++) {
    seen.push(...await page.locator('.origin-row').evaluateAll(rows => rows.map(row => row.dataset.id)));
    if (i < 4) await page.locator('#origin-next').click();
  }
  expect(new Set(seen).size).toBe(29);
  await expect(page.locator('#origin-next')).toBeDisabled();
  await page.locator('.origin-row').last().click();
  await expect(page.locator('#selected-ip')).toHaveText('192.0.2.29');

  entries['192.0.2.29'].reason = 'Updated synthetic fixture';
  delete entries['192.0.2.1'];
  // Exercise the existing refresh handler without depending on a minute-long poll.
  await page.locator('#retry-data').evaluate(button => button.click());
  await expect(page.locator('#selected-reason')).toHaveText('Updated synthetic fixture');
  await expect(page.locator('#group-label')).toContainText('28 IPs');
  await expect(page.locator('#origin-scope')).toHaveText('28 IN GROUP');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2)).toBe(true);
  const assertNoClipping = async () => {
    expect(await page.locator('.viewport').evaluate(el => el.scrollHeight <= el.clientHeight + 1),
      'Group controls and map legend fit inside the viewport, including short windows').toBe(true);
  };
  await assertNoClipping();
  if (info.project.name === 'desktop') {
    expect(await page.locator('.left-rail').evaluate(el => el.scrollHeight > el.clientHeight),
      'Long side panels scroll locally instead of stretching the map beyond the display').toBe(true);
    expect((await canvas.boundingBox()).height, 'The map fits the display with room for its controls').toBeLessThan(600);
    await page.setViewportSize({width:1201, height:700});
    await assertNoClipping();
    await page.setViewportSize({width:1440, height:1000});
  }

  // Capture the new controls with regional geography, not the intentionally
  // featureless interior of a single country at 128x magnification.
  await page.locator('#clear-group').click();
  await expect(page.locator('#group-summary')).toBeHidden();
  await page.locator('#reset-view').click();
  await expect(page.locator('#zoom-level')).toHaveText('1×');
  await page.locator('#region').selectOption('europe');
  await clickCentre();
  for (let i = 0; i < 4; i++) await page.locator('#zoom-in').click();
  await assertNoClipping();
  await page.mouse.move(page.viewportSize().width - 4, 4);
  await page.evaluate(() => { window.scrollTo(0, 0); document.activeElement?.blur(); });
  const results = await new AxeBuilder({page}).include('#main-content')
    .withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa']).analyze();
  expect(results.violations.map(({id,nodes}) => ({id, targets:nodes.map(node => node.target)}))).toEqual([]);
  await page.screenshot({path:info.outputPath('threat-map.png'), fullPage:true});

  await page.locator('#reset-view').click();
  await expect(page.locator('#group-summary')).toBeHidden();
  await expect(page.locator('#origin-scope')).toHaveText('SELECT AN IP');
});
