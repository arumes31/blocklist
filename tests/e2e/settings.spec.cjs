const {test, expect, unique} = require('./fixtures.cjs');

async function leaveHoverSidebar(page) {
  // Establish the pointer position after navigation, outside the hover rail.
  // Form fill() uses the keyboard and does not move the pointer away.
  await page.mouse.move(page.viewportSize().width - 4, 4);
  if (page.viewportSize().width >= 992) {
    await expect.poll(async () => {
      const box = await page.locator('.app-sidebar').boundingBox();
      return box.x + box.width;
    }).toBeLessThan(100);
  }
}

for (const [template, permissions] of [
  ['Fail2ban Template', ['block_ips']],
  ['Fortigate Template', ['block_ips', 'unblock_ips']],
  ['Webhook Template', ['block_ips', 'unblock_ips', 'whitelist_ips']],
  ['Auditor Template', ['export_data', 'view_ips']],
]) {
  test(`token template ${template} submits and persists its exact scopes`, async ({page}) => {
    await page.goto('/settings');
    await leaveHoverSidebar(page);
    const name = unique('token');
    await page.locator('#tokenForm [name=name]').fill(name);
    await page.locator('#tokenForm [name=allowed_ips]').fill('192.0.2.0/24');
    await page.getByRole('button', {name: template, exact: true}).click();
    page.on('dialog', dialog => dialog.dismiss());
    const request = page.waitForRequest(request => request.url().endsWith('/api/v1/settings/tokens') && request.method() === 'POST');
    await page.getByRole('button', {name: 'Create Token', exact: true}).click();
    const params = new URLSearchParams((await request).postData());
    expect(params.get('permissions').split(',').sort()).toEqual(permissions);
    const row = page.locator('#token-list tr').filter({hasText: name});
    await expect(row).toBeVisible();
    for (const permission of permissions) await expect(row).toContainText(permission);
    await expect(row).toContainText('192.0.2.0/24');
    await row.getByRole('button', {name: 'Edit', exact: true}).click();
    await row.getByRole('button', {name: 'Cancel', exact: true}).click();
    await row.getByRole('button', {name: 'Edit', exact: true}).click();
    for (const input of await row.locator('.perm-edit input').all()) await input.uncheck();
    await row.locator('.perm-edit input[value=view_ips]').check();
    await Promise.all([page.waitForEvent('load'), row.getByRole('button', {name: 'Save', exact: true}).click()]);
    await expect(row.locator('.perm-display')).toContainText('view_ips');
    await row.getByRole('button', {name: 'Revoke', exact: true}).click();
    await expect(row).toHaveCount(0);
  });
}

test('webhook named fields create a usable row and Delete removes only that webhook', async ({page}) => {
  await page.goto('/settings');
  await leaveHoverSidebar(page);
  const url = 'https://1.1.1.1/' + unique('hook');
  await page.getByLabel('URL', {exact: true}).fill(url);
  await page.locator('#webhookSecret').fill('test-only-signing-value');
  await page.locator('#webhookEvents').fill('block,unblock');
  await page.locator('#webhookGeoFilter').fill('AT,DE');
  await page.getByRole('button', {name: 'Add Webhook', exact: true}).click();
  const row = page.locator('#webhook-list tr').filter({hasText: url});
  await expect(row).toBeVisible();
  await expect(row).toContainText('block,unblock');
  await page.reload();
  await expect(row).toBeVisible();
  await row.getByRole('button', {name: 'Delete', exact: true}).click();
  await expect(row).toHaveCount(0);
});
