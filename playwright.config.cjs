const {defineConfig, devices} = require('@playwright/test');

// The runner owns this isolated stack. Never accept an arbitrary production URL.
if (!/^blocklist-e2e-[a-f0-9]{12}$/.test(process.env.E2E_PROJECT || '') ||
    !/^http:\/\/127\.0\.0\.1:\d+$/.test(process.env.E2E_BASE_URL || '') ||
    !/^ws:\/\/127\.0\.0\.1:\d+\/$/.test(process.env.E2E_BROWSER_WS_ENDPOINT || '')) {
  throw new Error('Run npm run test:ui to create the isolated test stack.');
}

module.exports = defineConfig({
  testDir: './tests/e2e',
  testMatch: '*.spec.cjs',
  timeout: 45000,
  expect: {timeout: 10000},
  workers: 1,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  updateSnapshots: 'none',
  snapshotPathTemplate: '{testDir}/snapshots/{testFilePath}/{arg}-{projectName}{ext}',
  reporter: [['list'], ['html', {open: 'never'}]],
  globalSetup: require.resolve('./tests/e2e/setup.cjs'),
  use: {
    baseURL: process.env.E2E_BASE_URL,
    storageState: process.env.E2E_AUTH_DIR + '/admin.json',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    locale: 'en-GB',
    timezoneId: 'UTC',
    connectOptions: {wsEndpoint: process.env.E2E_BROWSER_WS_ENDPOINT, exposeNetwork: '<loopback>'},
  },
  projects: [
    {name: 'desktop', use: {...devices['Desktop Chrome'], viewport: {width: 1440, height: 1000}}},
    {name: 'mobile', use: {...devices['Desktop Chrome'], viewport: {width: 390, height: 844}, isMobile: true, hasTouch: true}},
  ],
});
