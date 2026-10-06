const {chromium, expect} = require('@playwright/test');
const path = require('node:path');
const {login} = require('./fixtures.cjs');

module.exports = async function setup() {
  const baseURL = process.env.E2E_BASE_URL;
  const browser = await chromium.connect(process.env.E2E_BROWSER_WS_ENDPOINT, {exposeNetwork: '<loopback>'});
  try {
    const admin = await browser.newContext({baseURL});
    const page = await admin.newPage();
    await login(page);
    await admin.storageState({path: path.join(process.env.E2E_AUTH_DIR, 'admin.json')});
    for (const role of ['viewer', 'moderator', 'editor']) {
      const username = 'ui-' + role;
      const response = await admin.request.post('/admin_management/create', {
        headers: {Origin: baseURL},
        data: {username, password: process.env.E2E_PASSWORD, auth_source: 'local', role},
      });
      expect(response.ok(), `Create ${role} fixture`).toBeTruthy();
      const context = await browser.newContext({baseURL});
      await login(await context.newPage(), username);
      await context.storageState({path: path.join(process.env.E2E_AUTH_DIR, role + '.json')});
      await context.close();
    }
    await admin.close();
  } finally {
    await browser.close();
  }
};
