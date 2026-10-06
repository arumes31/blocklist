const {test, expect} = require('./fixtures.cjs');

const destinations = [
  ['/dashboard', 'Dashboard'], ['/threat-map', 'Threat Map'], ['/whitelist', 'Whitelist'],
  ['/excluded', 'Excluded'], ['/event-logs', 'Event logs'], ['/audit-logs', 'System audit logs'],
  ['/settings', 'Settings & Integrations'], ['/admin_management', 'Accounts'], ['/roles', 'Roles'],
  ['/docs', 'API Reference'],
];

test('all navigation destinations load, stay usable, and preserve desktop sidebar expansion', async ({page}, info) => {
  test.setTimeout(90000);
  await page.goto('/dashboard');
  const sidebar = page.locator('.app-sidebar');
  for (const [path, title] of destinations) {
    if (info.project.name === 'desktop') await sidebar.hover();
    await page.locator(`.app-navigation a[href="${path}"]`).click();
    await expect(page).toHaveURL(new RegExp(path + '$'));
    await expect(page.getByRole('heading', {level: 1})).toContainText(title);
    await expect(page.locator('#main-content')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2), `${path} has no page-wide horizontal overflow`).toBe(true);
    if (info.project.name === 'desktop') {
      await expect(page.locator('html')).toHaveAttribute('data-sidebar-navigation-open', '');
      await expect.poll(async () => (await sidebar.boundingBox()).x).toBeGreaterThanOrEqual(0);
    }
  }
  if (info.project.name === 'desktop') {
    await page.mouse.move(800, 80);
    await expect(page.locator('html')).not.toHaveAttribute('data-sidebar-navigation-open');
    await expect.poll(async () => { const box = await sidebar.boundingBox(); return box.x + box.width; }).toBeLessThan(100);
    await page.locator('.nav-roles').focus();
    await expect.poll(async () => (await sidebar.boundingBox()).x).toBeGreaterThanOrEqual(0);
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/\/roles$/);
    await expect(page.locator('.nav-roles')).toBeFocused();
  }
});

test('API documentation stays scrolled instead of resetting after render', async ({page}) => {
  await page.goto('/docs');
  const docs = page.locator('rapi-doc');
  await expect(docs.locator('.main-content')).toBeVisible();
  const scroller = docs.locator('.main-content');
  await expect.poll(() => scroller.evaluate(el => el.scrollHeight - el.clientHeight)).toBeGreaterThan(500);
  await scroller.hover();
  await page.mouse.wheel(0, 900);
  await expect.poll(() => scroller.evaluate(el => el.scrollTop)).toBeGreaterThan(300);
  // Observe several animation/render cycles: this specifically guards the reported reset loop.
  await page.waitForTimeout(1200);
  expect(await scroller.evaluate(el => el.scrollTop)).toBeGreaterThan(300);
  await page.mouse.wheel(0, 600);
  await expect.poll(() => scroller.evaluate(el => el.scrollTop)).toBeGreaterThan(600);
});

test('map view, layer, region, zoom, motion, and data filters respond', async ({page}) => {
  await page.emulateMedia({reducedMotion: 'reduce'});
  await page.goto('/threat-map');
  await expect(page.locator('#scene')).toBeVisible();
  await expect(page.locator('#pause-motion')).toHaveText('Enable motion');
  await page.locator('#pause-motion').click();
  await expect(page.locator('#pause-motion')).toHaveAttribute('aria-pressed', 'false');
  await page.locator('#pause-motion').click();
  await expect(page.locator('#pause-motion')).toHaveAttribute('aria-pressed', 'true');
  await page.locator('[data-view=flat]').click();
  await expect(page.locator('#flat-map')).toBeVisible();
  await expect(page.locator('#scene')).toBeHidden();
  await expect(page.locator('#flat-map .leaflet-overlay-pane svg')).toBeVisible();
  await page.locator('[data-layer=density]').click();
  await expect(page.locator('[data-layer=density]')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#toggle-cluster')).toBeDisabled();
  await page.locator('[data-layer=routes]').click();
  await expect(page.locator('#toggle-cluster')).toBeEnabled();
  await page.locator('#toggle-cluster').uncheck();
  await page.locator('#toggle-cluster').check();
  for (const region of ['europe', 'asia', 'americas']) {
    await page.locator('#region').selectOption(region);
    await expect(page.locator('#region')).toHaveValue(region);
  }
  await page.locator('#zoom-in').click();
  await page.locator('#zoom-out').click();
  await page.locator('#reset-view').click();
  await expect(page.locator('#region')).toHaveValue('global');
  await page.locator('#toggle-blocked').uncheck();
  await expect(page.locator('#toggle-all-blocked')).toBeDisabled();
  await page.locator('#toggle-blocked').check();
  await expect(page.locator('#toggle-all-blocked')).toBeEnabled();
  await page.locator('#toggle-all-blocked').uncheck();
  await page.locator('#toggle-all-blocked').check();
  await page.locator('#toggle-whitelist').check();
  await page.locator('#toggle-whitelist').uncheck();
  await page.locator('#toggle-paths').uncheck();
  await page.locator('#toggle-paths').check();
  await page.locator('[data-view=globe]').click();
  await expect(page.locator('[data-view=globe]')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#flat-map')).toBeHidden();
});

for (const path of ['/event-logs', '/audit-logs']) {
  test(`${path} filters submit on their own route and Reset clears them`, async ({page}) => {
    await page.goto(path);
    const choices = await page.getByLabel('Action', {exact: true}).locator('option').evaluateAll(options => options.map(option => option.value));
    expect(choices.length).toBeGreaterThan(1);
    const action = choices[1];
    await page.getByLabel('Actor', {exact: true}).fill('nonexistent-test-actor');
    await page.getByLabel('Action', {exact: true}).selectOption(action);
    await page.getByLabel('Search target or reason', {exact: true}).fill('no-match-test');
    await page.getByRole('button', {name: 'Filter', exact: true}).click();
    const url = new URL(page.url());
    expect(url.pathname).toBe(path);
    expect(Object.fromEntries(url.searchParams)).toEqual({actor: 'nonexistent-test-actor', action, query: 'no-match-test'});
    await expect(page.getByText('No matching activity', {exact: true})).toBeVisible();
    await page.getByRole('link', {name: 'Reset', exact: true}).click();
    await expect(page.getByLabel('Actor', {exact: true})).toHaveValue('');
    await expect(page.getByLabel('Action', {exact: true})).toHaveValue('');
    await expect(page.getByLabel('Search target or reason', {exact: true})).toHaveValue('');
  });
}

for (const role of ['viewer', 'moderator']) {
  test.describe(`${role} access`, () => {
    test.use({storageState: process.env.E2E_AUTH_DIR + `/${role}.json`});
    test('all pages remain readable, but account, role, and integration changes are unavailable', async ({page, api}) => {
      test.setTimeout(90000);
      for (const [path] of destinations) {
        expect((await page.goto(path)).ok(), `${role} can read ${path}`).toBe(true);
        await expect(page.getByRole('heading', {level: 1})).toBeVisible();
      }
      await page.goto('/roles');
      await expect(page.locator('#newRole')).toHaveCount(0);
      await expect(page.locator('#saveRole')).toHaveCount(0);
      await expect(page.locator('#roleName')).toBeDisabled();
      await page.goto('/admin_management');
      await expect(page.locator('#accountForm')).toHaveCount(0);
      await expect(page.locator('[data-account-action]')).toHaveCount(0);
      await page.goto('/settings');
      await expect(page.locator('#tokenForm')).toBeHidden();
      await expect(page.getByRole('button', {name: 'Add Webhook', exact: true})).toBeHidden();
      for (const endpoint of ['/api/v1/roles', '/admin_management/create', '/api/v1/settings/tokens']) {
        const denied = await api.post(endpoint, {data: {}});
        expect(denied.status(), `${role} cannot mutate ${endpoint}`).toBe(403);
      }
    });
  });
}
