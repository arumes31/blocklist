const {test, expect, unique} = require('./fixtures.cjs');
const {randomUUID} = require('node:crypto');

test('role create, permission count, discard, update, and delete persist', async ({page, api}) => {
  const name = unique('reviewer');
  await page.goto('/roles');
  await page.locator('#newRole').click();
  await page.getByLabel('Role name', {exact: true}).fill(name);
  await page.getByLabel('Role key', {exact: true}).fill(name);
  await page.getByLabel('Description', {exact: true}).fill('UI test role');
  await page.locator('[name=permission][value=gui_read]').check();
  await page.locator('[name=permission][value=view_ips]').check();
  await expect(page.locator('#permissionCount')).toHaveText('2 of 24 selected');
  await page.locator('#saveRole').click();
  const option = page.locator(`[data-role-id="${name}"]`);
  await expect(option).toBeVisible();
  await option.click();
  await expect(page.locator('#roleKey')).toHaveJSProperty('readOnly', true);
  await page.locator('#roleName').fill('Unsaved edit');
  await page.locator('#resetRole').click();
  await expect(page.locator('#roleName')).toHaveValue(name);
  await page.locator('#roleDescription').fill('Updated UI test role');
  await page.locator('#saveRole').click();
  await expect(option).toHaveAttribute('data-description', 'Updated UI test role');
  await option.click();
  page.once('dialog', dialog => dialog.dismiss());
  await page.locator('#deleteRole').click();
  await expect(option).toBeVisible();
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#deleteRole').click();
  await expect(option).toHaveCount(0);
  expect((await api.get('/api/v1/roles')).ok()).toBeTruthy();
});

test('built-in role deletion is unavailable and invalid role keys cannot submit', async ({page}) => {
  await page.goto('/roles');
  await page.locator('[data-role-id=editor]').click();
  await expect(page.locator('#deleteRole')).toBeHidden();
  await page.locator('#newRole').click();
  await page.locator('#roleName').fill('Invalid key');
  await page.locator('#roleKey').fill('INVALID KEY');
  await page.locator('#saveRole').click();
  expect(await page.locator('#roleKey').evaluate(el => el.validity.patternMismatch)).toBe(true);
  await expect(page.locator('#roleEditorTitle')).toHaveText('Create role');
});

test('role conflict and reauthentication errors are visible and restore submit controls', async ({page}) => {
  await page.goto('/roles');
  await page.locator('[data-role-id=viewer]').click();
  await page.route('**/api/v1/roles/viewer', route => route.fulfill({status: 409, json: {error: 'Role changed; refresh and retry.'}}));
  await page.locator('#saveRole').click();
  await expect(page.getByRole('status')).toContainText('Role changed');
  await expect(page.locator('#saveRole')).toBeEnabled();
  await page.route('**/api/v1/roles/viewer', route => route.fulfill({status: 403, json: {reauth_url: '/sudo'}}));
  await page.locator('#saveRole').click();
  await expect(page.getByRole('link', {name: 'Verify identity', exact: true})).toHaveAttribute('href', '/sudo?next=%2Froles');
});

test('local account creation, assignment, password dialog, MFA reset, and delete work', async ({page}) => {
  const username = unique('local');
  await page.goto('/admin_management');
  await page.locator('.account-create > summary').click();
  await page.getByLabel('Account name', {exact: true}).fill(username);
  await page.getByLabel('Initial password', {exact: true}).fill(process.env.E2E_PASSWORD);
  await page.locator('#accountForm [type=submit]').click();
  const row = page.locator('tbody tr').filter({has: page.getByText(username, {exact: true})});
  await expect(row).toBeVisible();
  await row.locator('select[name=role]').selectOption('moderator');
  await Promise.all([page.waitForEvent('load'), row.getByRole('button', {name: 'Apply', exact: true}).click()]);
  await expect(row.locator('select[name=role]')).toHaveValue('moderator');
  await row.getByRole('button', {name: 'Password', exact: true}).click();
  await expect(page.locator('#passwordDialog')).toBeVisible();
  await page.locator('#cancelPassword').click();
  await expect(page.locator('#passwordDialog')).toBeHidden();
  await row.getByRole('button', {name: 'Password', exact: true}).click();
  await page.getByLabel('New password', {exact: true}).fill(process.env.E2E_PASSWORD + 'x');
  await Promise.all([page.waitForEvent('load'), page.locator('#passwordForm [type=submit]').click()]);
  await expect(page.locator('#passwordDialog')).toBeHidden();
  page.once('dialog', dialog => dialog.dismiss());
  await row.getByRole('button', {name: 'Reset MFA', exact: true}).click();
  page.once('dialog', dialog => dialog.accept());
  const reset = page.waitForResponse(response => response.url().endsWith('/admin_management/change_totp') && response.status() === 200);
  await Promise.all([page.waitForEvent('load'), row.getByRole('button', {name: 'Reset MFA', exact: true}).click()]);
  await reset;
  await expect(row).toBeVisible();
  page.once('dialog', dialog => dialog.accept());
  await row.getByRole('button', {name: 'Delete', exact: true}).click();
  await expect(row).toHaveCount(0);
});

test('Entra provisioning accepts only UPN and role; inactive local fields are not submitted', async ({page}) => {
  const upn = unique('entra') + '@example.invalid';
  await page.goto('/admin_management');
  await page.locator('.account-create > summary').click();
  await page.getByLabel('Sign-in method', {exact: true}).selectOption('entra');
  await expect(page.locator('#newUsername')).toBeDisabled();
  await expect(page.locator('#newPassword')).toBeDisabled();
  await page.getByLabel('UPN', {exact: true}).fill(upn);
  const submitted = page.waitForRequest(request => request.url().endsWith('/admin_management/create') && request.method() === 'POST');
  await page.locator('#accountForm [type=submit]').click();
  expect((await submitted).postDataJSON()).toEqual({auth_source: 'entra', entra_upn: upn, role: 'viewer'});
  const row = page.locator('tbody tr').filter({hasText: upn});
  await expect(row).toContainText('Pending first sign-in');
  await expect(row.getByRole('button', {name: 'Password', exact: true})).toHaveCount(0);
  await row.getByLabel('Keep local role override').check();
  await Promise.all([page.waitForEvent('load'), row.getByRole('button', {name: 'Apply', exact: true}).click()]);
  await expect(row.getByLabel('Keep local role override')).toBeChecked();
  page.once('dialog', dialog => dialog.accept());
  await row.getByRole('button', {name: 'Delete', exact: true}).click();
  await expect(row).toHaveCount(0);
});

test('recovery account has no destructive controls', async ({page}) => {
  await page.goto('/admin_management');
  const row = page.locator('tbody tr').filter({has: page.getByText('ui-recovery', {exact: true})});
  await expect(row).toContainText('Protected');
  await expect(row.locator('button')).toHaveCount(0);
});

test('bound Entra accounts display UPN but role and delete actions keep the account key', async ({page, api}, info) => {
  const username = unique('legacy-entra-binding');
  const upn = unique('long.account.name.for.responsive.display') + '@example.invalid';
  const created = await api.post('/admin_management/create', {data: {
    username, auth_source: 'entra', entra_upn: upn, role: 'viewer',
    entra_tenant_id: randomUUID(), entra_object_id: randomUUID(),
  }});
  expect(created.ok()).toBeTruthy();
  await page.goto('/admin_management');
  await page.mouse.move(page.viewportSize().width - 4, 4);
  const row = page.locator('tbody tr').filter({has: page.locator('.account-name', {hasText: upn})});
  await expect(row.locator('.account-name')).toHaveText(upn);
  await expect(row.getByLabel('Role for ' + upn, {exact: true})).toHaveValue('viewer');
  await expect(row.getByText(username, {exact: true})).toBeHidden();
  await row.getByText('Identity binding', {exact: true}).click();
  await expect(row.getByText(username, {exact: true})).toBeVisible();
  await row.getByText('Identity binding', {exact: true}).click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2)).toBe(true);
  expect(await row.locator('.account-name').evaluate(el => el.scrollWidth <= el.clientWidth + 1)).toBe(true);
  await page.screenshot({path: info.outputPath('entra-account-upn.png'), fullPage: true});
  await row.getByLabel('Role for ' + upn, {exact: true}).selectOption('moderator');
  const roleRequest = page.waitForRequest(request => request.url().endsWith('/admin_management/change_role') && request.method() === 'POST');
  await Promise.all([page.waitForEvent('load'), row.getByRole('button', {name: 'Apply', exact: true}).click()]);
  expect((await roleRequest).postDataJSON().username).toBe(username);
  await expect(row.getByLabel('Role for ' + upn, {exact: true})).toHaveValue('moderator');
  const confirmation = page.waitForEvent('dialog');
  const clickDelete = row.getByRole('button', {name: 'Delete', exact: true}).click();
  const dialog = await confirmation;
  const message = dialog.message();
  const deleteRequest = page.waitForRequest(request => request.url().endsWith('/admin_management/delete') && request.method() === 'POST');
  await dialog.accept();
  await clickDelete;
  expect(message).toContain(upn);
  expect(message).not.toContain(username);
  expect((await deleteRequest).postDataJSON()).toEqual({username});
  await expect(row).toHaveCount(0);
});
