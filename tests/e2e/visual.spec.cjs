const {test, expect} = require('./fixtures.cjs');

// Only deterministic form surfaces are captured. Real data and canvas/APNG
// animation are tested elsewhere; freezing them must not alter production motion.
async function capture(locator, name) {
  await locator.page().evaluate(() => document.fonts.ready);
  // The left edge opens the hover sidebar. Keep it outside the capture and
  // wait for its closing transition instead of recording an overlay.
  const page = locator.page();
  await page.mouse.move(page.viewportSize().width - 4, 4);
  await locator.page().evaluate(() => document.activeElement?.blur());
  const sidebar = page.locator('.app-sidebar');
  if (page.viewportSize().width >= 992 && await sidebar.count()) {
    await expect.poll(async () => {
      const box = await sidebar.boundingBox();
      return box.x + box.width;
    }).toBeLessThan(100);
  }
  await expect(locator).toHaveScreenshot(name, {
    animations: 'disabled', caret: 'hide', scale: 'css', maxDiffPixelRatio: 0.001,
  });
}

test('visual: role editor', async ({page}) => {
  await page.goto('/roles');
  await page.locator('#newRole').click();
  await expect(page.locator('#roleEditorTitle')).toHaveText('Create role');
  await capture(page.locator('.role-editor'), 'role-editor.png');
});

test('visual: account creation fields', async ({page}) => {
  await page.goto('/admin_management');
  await page.locator('.account-create > summary').click();
  await capture(page.locator('.account-create'), 'account-local.png');
  await page.getByLabel('Sign-in method', {exact: true}).selectOption('entra');
  await expect(page.getByLabel('UPN', {exact: true})).toBeVisible();
  await capture(page.locator('.account-create'), 'account-entra.png');
});

test('visual: block dialog', async ({page}) => {
  await page.goto('/dashboard');
  await page.locator('.page-actions').getByRole('button', {name: 'Block IP', exact: true}).click();
  await expect(page.locator('#blockModal')).toBeVisible();
  await capture(page.locator('#blockModal .modal-content'), 'block-dialog.png');
});

test.describe('public sign-in', () => {
  test.use({storageState: {cookies: [], origins: []}});
  test('visual: login form', async ({page}) => {
    await page.goto('/login');
    await page.getByRole('button', {name: 'Pause animation', exact: true}).click();
    // The translucent panel otherwise includes a different random canvas frame.
    await page.locator('#loginScene').evaluate(canvas => { canvas.style.visibility = 'hidden'; });
    await capture(page.locator('#loginContainer'), 'login-form.png');
  });
});
