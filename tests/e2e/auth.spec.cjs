const {test, expect, login, totp} = require('./fixtures.cjs');
test.use({storageState: {cookies: [], origins: []}});

test('local password and authenticator login, logout, and protected navigation', async ({page}) => {
  await login(page);
  await page.locator('.app-sidebar').hover();
  await page.getByRole('link', {name: 'Sign out', exact: true}).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.goto('/roles');
  await expect(page).toHaveURL(/\/login/);
});

test('invalid password and invalid authenticator cannot open the workspace', async ({page}) => {
  await page.goto('/login');
  await page.getByLabel('Username', {exact: true}).fill('ui-recovery');
  await page.getByLabel('Password', {exact: true}).fill('deliberately-wrong');
  await page.getByRole('button', {name: 'Continue', exact: true}).click();
  await expect(page.locator('.error-message')).toBeVisible();
  await loginFirstFactor(page);
  const invalid = String((Number(totp(process.env.E2E_TOTP_SECRET)) + 12345) % 1000000).padStart(6, '0');
  await page.locator('#totp').fill(invalid);
  await page.locator('#loginForm [type=submit]').click();
  await expect(page.locator('.error-message')).toBeVisible();
  await expect(page).not.toHaveURL(/\/dashboard$/);
});

async function loginFirstFactor(page) {
  await page.goto('/login');
  await page.getByLabel('Username', {exact: true}).fill('ui-recovery');
  await page.getByLabel('Password', {exact: true}).fill(process.env.E2E_PASSWORD);
  await page.getByRole('button', {name: 'Continue', exact: true}).click();
  await expect(page.locator('#totp')).toBeVisible();
}

async function sceneFingerprint(page) {
  return page.locator('#loginScene').evaluate(canvas => {
    const pixels = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height).data;
    let hash = 2166136261;
    for (let index = 0; index < pixels.length; index += 64) {
      for (let channel = 0; channel < 3; channel++) hash = Math.imul(hash ^ pixels[index + channel], 16777619);
    }
    return hash >>> 0;
  });
}

test('login mesh, all presets, pause/play, persisted choice, raw API and health links', async ({page}) => {
  await page.emulateMedia({reducedMotion: 'reduce'});
  await page.goto('/login');
  await expect(page.locator('#backgroundVariant')).toHaveValue('mesh');
  await expect(page.locator('#loginScene')).toHaveAttribute('data-motion', 'playing');
  await expect(page.locator('.animated-logo')).toBeVisible();
  const playingFrame = await sceneFingerprint(page);
  await expect.poll(() => sceneFingerprint(page)).not.toBe(playingFrame);
  await page.getByRole('button', {name: 'Pause animation', exact: true}).click();
  await expect(page.locator('#loginScene')).toHaveAttribute('data-motion', 'paused');
  await expect(page.locator('.animated-logo')).toBeHidden();
  const pausedFrame = await sceneFingerprint(page);
  await page.waitForTimeout(150);
  expect(await sceneFingerprint(page)).toBe(pausedFrame);
  for (const variant of ['original', 'ember', 'vortex', 'aurora', 'mesh', 'sonar']) {
    await page.getByLabel('Background', {exact: true}).selectOption(variant);
    await expect(page.locator('#loginScene')).toHaveAttribute('data-motion', 'paused');
    await expect(page.locator('#backgroundDescription')).not.toBeEmpty();
  }
  await page.getByRole('button', {name: 'Play animation', exact: true}).click();
  await expect(page.locator('#loginScene')).toHaveAttribute('data-motion', 'playing');
  await page.reload();
  await expect(page.locator('#backgroundVariant')).toHaveValue('sonar');
  await expect(page.locator('#loginScene')).toHaveAttribute('data-motion', 'playing');
  await expect(page.getByRole('link', {name: 'RAW API', exact: true})).toHaveAttribute('href', '/api/v1/raw');
  await page.getByRole('link', {name: 'System health', exact: true}).click();
  await expect(page).toHaveURL(/\/health$/);
});
