const AxeBuilder = require('@axe-core/playwright').default;
const {test, expect} = require('./fixtures.cjs');

async function scan(page) {
  await page.evaluate(() => document.fonts.ready);
  const sidebar = page.locator('.app-sidebar');
  if (await sidebar.count()) {
    // Hover/focus can start the label fade after navigation. Axe must sample the
    // settled state, not a partially transparent frame. Keep real motion enabled.
    await expect.poll(() => sidebar.evaluate(el => el.getAnimations({subtree: true})
      .filter(animation => animation instanceof CSSTransition && animation.playState !== 'finished').length),
    {message: 'Sidebar transitions finish before checking accessibility'}).toBe(0);
  }
  const result = await new AxeBuilder({page}).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
  expect(result.violations.map(({id, impact, nodes}) => ({id, impact,
    nodes: nodes.map(({target, failureSummary}) => ({target, failureSummary}))})),
    'No automatically detectable WCAG A/AA violations').toEqual([]);
}

for (const route of ['/dashboard', '/threat-map', '/whitelist', '/excluded', '/event-logs',
  '/audit-logs', '/settings', '/admin_management', '/roles', '/docs']) {
  test(`accessibility: ${route}`, async ({page}) => {
    await page.goto(route);
    await expect(page.locator('h1').first()).toBeVisible();
    // The browser's default pointer at (0, 0) can open the desktop hover rail.
    await page.mouse.move(page.viewportSize().width - 4, 4);
    await test.step('Page with collapsed desktop rail or mobile navigation', () => scan(page));
    if (page.viewportSize().width >= 992) {
      await expect(page.locator('.brand-caption')).toHaveCSS('opacity', '0');
      await page.locator('.app-sidebar').hover();
      await test.step('Page with expanded desktop navigation', () => scan(page));
      await expect(page.locator('.brand-caption')).toHaveCSS('opacity', '1');
      await expect(page.locator('.account-label')).toHaveCSS('opacity', '1');
    }
  });
}

test('accessibility: desktop sidebar remains readable on keyboard focus and closes on exit', async ({page}) => {
  test.skip(page.viewportSize().width < 992, 'Mobile navigation has no hover rail');
  await page.goto('/audit-logs');
  await page.mouse.move(page.viewportSize().width - 4, 4);
  await scan(page);
  await page.locator('.nav-audit-logs').focus();
  await scan(page);
  await expect(page.locator('.nav-audit-logs')).toBeFocused();
  await expect(page.locator('.brand-caption')).toHaveCSS('opacity', '1');
  await expect(page.locator('.account-label')).toHaveCSS('opacity', '1');
  await page.getByLabel('Actor', {exact: true}).focus();
  await scan(page);
  await expect(page.locator('.brand-caption')).toHaveCSS('opacity', '0');
  await expect(page.locator('.account-label')).toHaveCSS('opacity', '0');
});

test('accessibility: account creation local and Entra forms', async ({page}) => {
  await page.goto('/admin_management');
  await page.locator('.account-create > summary').click();
  await scan(page);
  await page.getByLabel('Sign-in method', {exact: true}).selectOption('entra');
  await expect(page.getByLabel('UPN', {exact: true})).toBeVisible();
  await scan(page);
});

test('accessibility: create role and block dialog', async ({page}) => {
  await page.goto('/roles');
  await page.locator('#newRole').click();
  await scan(page);
  await page.goto('/dashboard');
  await page.locator('.page-actions').getByRole('button', {name: 'Block IP', exact: true}).click();
  await expect(page.locator('#blockModal')).toBeVisible();
  await scan(page);
});

test.describe('public sign-in', () => {
  test.use({storageState: {cookies: [], origins: []}});
  test('accessibility: login and keyboard form navigation', async ({page}) => {
    await page.goto('/login');
    await scan(page);
    const username = page.getByLabel('Username', {exact: true});
    await username.focus();
    await expect(username).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.getByLabel('Password', {exact: true})).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', {name: 'Continue', exact: true})).toBeFocused();
  });
});
