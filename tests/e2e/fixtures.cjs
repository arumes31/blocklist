const {test: base, expect} = require('@playwright/test');
const {randomBytes} = require('node:crypto');
const {totp} = require('./totp.cjs');

const unique = prefix => prefix + '-' + randomBytes(5).toString('hex');

async function login(page, username = 'ui-recovery', password = process.env.E2E_PASSWORD, secret = process.env.E2E_TOTP_SECRET) {
  await page.goto('/login');
  await page.getByLabel('Username', {exact: true}).fill(username);
  await page.getByLabel('Password', {exact: true}).fill(password);
  await page.getByRole('button', {name: 'Continue', exact: true}).click();
  await expect(page.locator('#totp')).toBeVisible();
  const setup = page.locator('input[name="setup_secret"]');
  if (await setup.count()) secret = await setup.inputValue();
  await page.locator('#totp').fill(totp(secret));
  await page.locator('#loginForm [type="submit"]').click();
  await expect(page).toHaveURL(/\/dashboard$/);
  return secret;
}

const test = base.extend({
  api: async ({playwright, page, baseURL}, use) => {
    const api = await playwright.request.newContext({
      baseURL, storageState: await page.context().storageState(), extraHTTPHeaders: {Origin: baseURL},
    });
    await use(api);
    await api.dispose();
  },
  page: async ({page, storageState, baseURL}, use) => {
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    if (typeof storageState === 'string' && storageState.endsWith('/admin.json')) {
      const verified = await page.request.post('/sudo', {
        headers: {Origin: baseURL}, form: {totp: totp(process.env.E2E_TOTP_SECRET), next: '/dashboard'},
      });
      expect(verified.ok(), 'Refresh test administrator sudo session').toBeTruthy();
    }
    await use(page);
    expect(errors, 'No uncaught browser errors').toEqual([]);
  },
});

module.exports = {test, expect, unique, login, totp};
