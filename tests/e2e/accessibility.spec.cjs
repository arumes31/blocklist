const AxeBuilder = require('@axe-core/playwright').default;
const {test, expect} = require('./fixtures.cjs');

async function scan(page) {
  await page.evaluate(() => document.fonts.ready);
  const result = await new AxeBuilder({page}).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
  expect(result.violations.map(({id, impact, nodes}) => ({id, impact, targets: nodes.map(n => n.target)})),
    'No automatically detectable WCAG A/AA violations').toEqual([]);
}

for (const route of ['/dashboard', '/threat-map', '/whitelist', '/excluded', '/event-logs',
  '/audit-logs', '/settings', '/admin_management', '/roles', '/docs']) {
  test(`accessibility: ${route}`, async ({page}) => {
    await page.goto(route);
    await expect(page.locator('h1').first()).toBeVisible();
    await scan(page);
  });
}

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
