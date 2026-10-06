const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const { createHmac } = require('node:crypto');

// Synthetic fixture only: base32 JBSWY3DPEHPK3PXP. No production identity is used.
function totp() {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const hash = createHmac('sha1', Buffer.from('48656c6c6f21deadbeef', 'hex')).update(counter).digest();
  const offset = hash[19] & 15;
  return String((hash.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0');
}

test('API health, embedded assets and authentication boundary', async ({ request }) => {
  expect((await request.get('/health')).status()).toBe(200);
  expect((await request.get('/api/v1/raw')).status()).toBe(200);
  expect((await request.get('/api/v1/ips')).status()).toBe(401);
  expect((await request.get('/api/v1/ips', { headers: { Authorization: 'Bearer invalid' } })).status()).toBe(401);
  expect((await request.get('/api/v1/ips', {
    headers: { Authorization: `Bearer ${process.env.CI_API_TOKEN}` },
  })).status()).toBe(200);
  expect((await request.get('/api/v1/stats', {
    headers: { Authorization: `Bearer ${process.env.CI_API_TOKEN}` },
  })).status()).toBe(403);
  const logo = await request.get('/cd/logo.png');
  expect(logo.status()).toBe(200);
  expect(logo.headers()['content-type']).toContain('image/png');
  const schema = await request.get('/openapi.json');
  expect(schema.status()).toBe(200);
  expect((await schema.json()).paths).toHaveProperty('/api/v1/ips');
});

test('login visual baseline', async ({ page }) => {
  await page.goto('/login');
  await expect(page.locator('#username')).toBeVisible();
  // Exclude the intentionally animated background; keep the entire form and controls.
  await expect(page.locator('#loginContainer')).toHaveScreenshot('login.png', {
    animations: 'disabled', caret: 'hide',
    style: 'canvas { visibility: hidden !important; }',
  });
});

test('login accessibility', async ({ page }) => {
  await page.goto('/login');
  await expect(page.locator('#username')).toBeVisible();
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(results.violations).toEqual([]);
});

test('password and TOTP login, dashboard, API session and logout', async ({ page }) => {
  await page.goto('/login');
  await page.locator('#username').fill('ci-admin');
  await page.locator('#password').fill(process.env.CI_ADMIN_PASSWORD);
  await page.getByRole('button', { name: 'LOGIN', exact: true }).click();
  await expect(page.locator('#totp')).toBeVisible();
  await page.locator('#totp').fill(totp());
  await page.getByRole('button', { name: 'Authorize Access', exact: true }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  expect((await page.request.get('/api/v1/ips')).status()).toBe(200);
  await page.goto('/logout');
  await expect(page).toHaveURL(/\/login$/);
  expect((await page.request.get('/api/v1/ips')).status()).toBe(401);
});
