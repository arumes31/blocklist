const {test, expect, unique, login} = require('./fixtures.cjs');
const {randomUUID} = require('node:crypto');
const AxeBuilder = require('@axe-core/playwright').default;

test('account search, combined filters, status actions and errors retain the right identity', async ({page, api}, info) => {
  const username = unique('bound-status');
  const upn = unique('search.person') + '@example.invalid';
  expect((await api.post('/admin_management/create', {data: {
    username, entra_upn: upn, auth_source: 'entra', role: 'viewer',
    entra_tenant_id: randomUUID(), entra_object_id: randomUUID(),
  }})).ok()).toBeTruthy();
  try {
    await page.goto('/admin_management');
    await page.mouse.move(page.viewportSize().width - 4, 4);
    const row = page.locator('[data-account-row]').filter({has: page.locator('.account-name', {hasText: upn})});
    const shown = page.locator('[data-account-row]:visible');
    await page.getByLabel('Name or UPN', {exact: true}).fill(upn.toUpperCase());
    await expect(shown).toHaveCount(1);
    await page.getByLabel('Sign-in source', {exact: true}).selectOption('local');
    await expect(page.locator('#accountEmpty')).toBeVisible();
    await expect(page.locator('#accountCount')).toContainText('0 of');
    await page.getByLabel('Sign-in source', {exact: true}).selectOption('entra');
    await expect(row).toBeVisible();
    await page.reload();
    await expect(page.locator('#accountSearch')).toHaveValue(upn.toUpperCase());
    await expect(page.locator('#accountSource')).toHaveValue('entra');
    await page.locator('#accountSearch').fill(username);
    await expect(shown).toHaveCount(1);
    await expect(row.locator('.account-state')).toHaveText('Active');
    page.once('dialog', dialog => dialog.dismiss());
    await row.getByRole('button', {name: 'Disable', exact: true}).click();
    await expect(row.locator('.account-state')).toHaveText('Active');
    await page.route('**/admin_management/change_status', route => route.fulfill({status: 409, json: {error: 'Account changed. Refresh and try again.'}}));
    page.once('dialog', dialog => dialog.accept());
    await row.getByRole('button', {name: 'Disable', exact: true}).click();
    await expect(page.locator('#identityStatus')).toContainText('Account changed');
    await expect(row.getByRole('button', {name: 'Disable', exact: true})).toBeEnabled();
    await expect(row.locator('.account-state')).toHaveText('Active');
    await page.unroute('**/admin_management/change_status');
    page.once('dialog', async dialog => {
      expect(dialog.message()).toContain(upn);
      expect(dialog.message()).toContain('30 seconds');
      await dialog.accept();
    });
    const request = page.waitForRequest(request => request.url().endsWith('/admin_management/change_status'));
    await Promise.all([page.waitForEvent('load'), row.getByRole('button', {name: 'Disable', exact: true}).click()]);
    expect((await request).postDataJSON()).toEqual({username, disabled: true});
    await expect(row.locator('.account-state')).toHaveText('Disabled');
    await expect(page.locator('#accountCount')).toContainText('1 of');
    await expect(page.locator('#accountCount')).toContainText('0 active');
    await page.locator('#accountState').selectOption('active');
    await expect(page.locator('#accountEmpty')).toBeVisible();
    await page.locator('#accountState').selectOption('disabled');
    await expect(row).toBeVisible();
    await page.locator('#clearAccountFilters').click();
    await expect(page.locator('#accountSearch')).toBeFocused();
    await expect(page.locator('#clearAccountFilters')).toBeDisabled();
    await expect(page).toHaveURL(/\/admin_management$/);
    await page.evaluate(() => { document.activeElement?.blur(); window.scrollTo(0, 0); });
    await page.mouse.move(page.viewportSize().width - 4, 4);
    await page.evaluate(() => document.fonts.ready);
    if (page.viewportSize().width >= 992) {
      await expect.poll(async () => {
        const bounds = await page.locator('.app-sidebar').boundingBox();
        return bounds.x + bounds.width;
      }).toBeLessThan(100);
    }
    await expect.poll(() => page.locator('.app-sidebar').evaluate(el => el.getAnimations({subtree: true})
      .filter(animation => animation instanceof CSSTransition && animation.playState !== 'finished').length)).toBe(0);
    const accessibility = await new AxeBuilder({page}).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
    expect(accessibility.violations).toEqual([]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({path: info.outputPath('accounts-status.png'), fullPage: true, animations: 'disabled', caret: 'hide'});
    if (page.viewportSize().width < 992) {
      await row.getByRole('button', {name: 'Enable', exact: true}).scrollIntoViewIfNeeded();
      await page.screenshot({path: info.outputPath('accounts-status-controls.png'), animations: 'disabled', caret: 'hide'});
    }
    page.once('dialog', dialog => dialog.accept());
    await Promise.all([page.waitForEvent('load'), row.getByRole('button', {name: 'Enable', exact: true}).click()]);
    await expect(row.locator('.account-state')).toHaveText('Active');
  } finally {
    expect((await api.post('/admin_management/delete', {data: {username}})).ok()).toBeTruthy();
  }
});

test('disable blocks real sessions, password sign-in, basic auth and API tokens; enable preserves tokens', async ({page, api, browser, baseURL}) => {
  test.setTimeout(120000);
  const username = unique('access-status');
  expect((await api.post('/admin_management/create', {data: {
    username, password: process.env.E2E_PASSWORD, auth_source: 'local', role: 'editor',
  }})).ok()).toBeTruthy();
  const context = await browser.newContext({baseURL, storageState: {cookies: [], origins: []}});
  const userPage = await context.newPage();
  let oldSession;
  try {
    const secret = await login(userPage, username);
    await userPage.goto('/admin_management');
    const self = userPage.locator('[data-account-row]').filter({has: userPage.getByText(username, {exact: true})});
    await expect(self).toContainText('Your account');
    await expect(self.locator('[data-account-action=status]')).toHaveCount(0);
    expect((await context.request.post('/admin_management/change_status', {
      headers: {Origin: baseURL}, data: {username, disabled: true},
    })).status()).toBe(403);
    const created = await context.request.post('/api/v1/settings/tokens', {
      headers: {Origin: baseURL}, form: {name: unique('status-token'), permissions: 'view_ips'},
    });
    expect(created.ok()).toBeTruthy();
    const token = JSON.parse(created.headers()['hx-trigger']).newToken;
    const bearer = {headers: {Authorization: 'Bearer ' + token}};
    const basic = {headers: {Authorization: 'Basic ' + Buffer.from(username + ':' + process.env.E2E_PASSWORD).toString('base64')}};
    expect((await api.get('/api/v1/ips', bearer)).status()).toBe(200);
    expect((await api.get('/api/v1/whitelists-raw', basic)).status()).toBe(200);
    // Keep a pristine copy to prove a session is still rejected after re-enabling.
    oldSession = await browser.newContext({baseURL, storageState: await context.storageState()});
    await userPage.evaluate(() => new Promise((resolve, reject) => {
      window.statusTestSocketClosed = false;
      const socket = new WebSocket(location.origin.replace(/^http/, 'ws') + '/ws');
      socket.onopen = resolve;
      socket.onerror = () => reject(new Error('Test live connection failed to open'));
      socket.onclose = () => { window.statusTestSocketClosed = true; };
    }));
    expect((await api.post('/admin_management/change_status', {data: {username, disabled: true}})).ok()).toBeTruthy();
    expect((await api.get('/api/v1/ips', bearer)).status()).toBe(401);
    await expect.poll(() => userPage.evaluate(() => window.statusTestSocketClosed),
      {timeout: 35000, message: 'Disabled account live connection closes at the 30-second recheck'}).toBe(true);
    // This request must not borrow an enabled administrator's browser session.
    expect((await context.request.get('/api/v1/whitelists-raw', basic)).status()).toBe(401);
    await userPage.goto('/dashboard');
    await expect(userPage).toHaveURL(/\/login$/);
    await userPage.getByLabel('Username', {exact: true}).fill(username);
    await userPage.getByLabel('Password', {exact: true}).fill(process.env.E2E_PASSWORD);
    await userPage.getByRole('button', {name: 'Continue', exact: true}).click();
    await expect(userPage.locator('.error-message')).toBeVisible();
    await expect(userPage.locator('#totp')).toHaveCount(0);
    expect((await api.post('/admin_management/change_status', {data: {username, disabled: false}})).ok()).toBeTruthy();
    const previous = await oldSession.newPage();
    await previous.goto('/dashboard');
    await expect(previous).toHaveURL(/\/login$/);
    expect((await api.get('/api/v1/ips', bearer)).status()).toBe(200);
    expect((await context.request.get('/api/v1/whitelists-raw', basic)).status()).toBe(200);
    await login(userPage, username, process.env.E2E_PASSWORD, secret);
    expect((await context.request.get('/api/v1/ips')).status()).toBe(200);
    await page.goto('/audit-logs');
    await page.getByLabel('Action', {exact: true}).selectOption('DISABLE_ADMIN');
    await page.getByLabel('Search target or reason', {exact: true}).fill(username);
    await page.getByRole('button', {name: 'Filter', exact: true}).click();
    await expect(page.locator('tbody')).toContainText(username);
    await expect(page.locator('tbody')).toContainText('DISABLE_ADMIN');
  } finally {
    await oldSession?.close();
    await context.close();
    expect((await api.post('/admin_management/delete', {data: {username}})).ok()).toBeTruthy();
  }
});

test.describe('read-only account search', () => {
  test.use({storageState: process.env.E2E_AUTH_DIR + '/viewer.json'});
  test('viewer can filter accounts but cannot change status', async ({page, api}) => {
    await page.goto('/admin_management');
    await page.locator('#accountSearch').fill('UI-EDITOR');
    await expect(page.locator('[data-account-row]:visible')).toHaveCount(1);
    await expect(page.locator('[data-account-action=status]')).toHaveCount(0);
    expect((await api.post('/admin_management/change_status', {data: {username: 'ui-editor', disabled: true}})).status()).toBe(403);
  });
});
