const fs = require('node:fs');
const path = require('node:path');
const AxeBuilder = require('@axe-core/playwright').default;
const {test, expect} = require('./fixtures.cjs');

test('threat-map panels support keyboard scrolling with empty and populated content', async ({page}, info) => {
  await page.emulateMedia({reducedMotion:'reduce'});
  // Keep synthetic stream events visible without stopping browser scrolling or
  // timers. These responses and messages never reach the application database.
  await page.clock.setFixedTime(new Date());
  const entries = {};
  let socket;
  await page.route('**/api/v1/ips_list', route => route.fulfill({json:entries}));
  await page.route('**/api/v1/stats', route => route.fulfill({json:{
    active_blocks:Object.keys(entries).length, day:0, hour:0,
    whitelisted:0, blocks_minute:0, top_countries:[],
  }}));
  await page.routeWebSocket('**/ws', ws => { socket = ws; });
  await page.goto('/threat-map');
  await expect(page.locator('#coverage-status')).toContainText('0 loaded / 0 reported');
  await expect(page.locator('#origin-prev')).toBeDisabled();
  await expect(page.locator('#origin-next')).toBeDisabled();

  const left = page.getByRole('complementary', {name:'Threat summary', exact:true});
  const right = page.getByRole('complementary', {name:'Live activity and IP details', exact:true});
  const stream = page.getByRole('list', {name:'Recent blocklist events', exact:true});
  const assertKeyboardScroll = async locator => {
    await expect(locator).toBeFocused();
    expect(await locator.evaluate(el => el.scrollHeight > el.clientHeight),
      'Fixture must overflow the scroll region').toBe(true);
    await locator.evaluate(el => { el.scrollTop = 0; });
    await page.keyboard.press('PageDown');
    await expect.poll(() => locator.evaluate(el => el.scrollTop)).toBeGreaterThan(0);
    await expect(locator).toBeFocused();
    await expect(locator).toHaveCSS('outline-style', 'solid');
  };

  // Reach the empty summary with Tab navigation, not mouse/programmatic focus.
  await page.locator('#map-controls').focus();
  await page.keyboard.press('Shift+Tab');
  await expect(left).toBeFocused();
  if (info.project.name === 'desktop') await assertKeyboardScroll(left);
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', {name:'Globe', exact:true})).toBeFocused();

  entries['192.0.2.1'] = {
    reason:'Synthetic long detail for keyboard scroll coverage. '.repeat(12),
    added_by:'UI regression fixture',
    geolocation:{latitude:47, longitude:17, country:'Austria', city:'Synthetic location'},
  };
  await page.locator('#retry-data').evaluate(button => button.click());
  await page.locator('.origin-row').click();
  await expect(page.locator('#selected-ip')).toHaveText('192.0.2.1');
  await expect.poll(() => Boolean(socket)).toBe(true);
  for (let i = 1; i <= 12; i++) {
    socket.send(JSON.stringify({action:'unblock', data:{ip:`198.51.100.${i}`}}));
  }
  await expect(stream.locator('li')).toHaveCount(12);

  await page.locator('#pause-motion').focus();
  await page.keyboard.press('Tab');
  await expect(right).toBeFocused();
  if (info.project.name === 'desktop') await assertKeyboardScroll(right);
  await page.keyboard.press('Tab');
  await expect(stream).toBeFocused();
  await assertKeyboardScroll(stream);
  await expect(stream).toHaveCSS('outline-offset', '-2px');
  await page.keyboard.press('Shift+Tab');
  await expect(right).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  await expect(page.locator('#pause-motion')).toBeFocused();

  await page.mouse.move(page.viewportSize().width - 4, 4);
  const result = await new AxeBuilder({page}).include('#main-content')
    .withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa']).analyze();
  expect(result.violations.map(({id,nodes}) => ({id, targets:nodes.map(node => node.target)}))).toEqual([]);

  // Capture the existing design's keyboard focus treatment on both viewports.
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  await expect(stream).toBeFocused();
  const reviewDir = path.resolve(__dirname, '../../.impeccable/review');
  fs.mkdirSync(reviewDir, {recursive:true});
  await page.screenshot({path:path.join(reviewDir, `threat-map-scroll-${info.project.name}.png`)});
});
