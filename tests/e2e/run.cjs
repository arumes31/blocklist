const {spawnSync} = require('node:child_process');
const {randomBytes} = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {base32} = require('./totp.cjs');

const root = path.resolve(__dirname, '../..');
const candidate = process.env.E2E_IMAGE;
if (candidate && !/^ghcr\.io\/[a-z0-9._-]+\/[a-z0-9._-]+@sha256:[a-f0-9]{64}$/.test(candidate)) {
  throw new Error('E2E_IMAGE must be a GHCR image pinned to its immutable sha256 digest.');
}
const project = 'blocklist-e2e-' + randomBytes(6).toString('hex');
const authDir = fs.mkdtempSync(path.join(os.tmpdir(), 'blocklist-e2e-'));
const envFile = path.join(authDir, 'compose.env');
// An explicit empty env file prevents Compose from reading the developer's .env.
fs.writeFileSync(envFile, '# Test stack configuration comes only from generated process variables.\n');
const env = {
  ...process.env,
  E2E_PROJECT: project,
  E2E_IMAGE: candidate || project + '-app',
  E2E_AUTH_DIR: authDir,
  E2E_DB_PASSWORD: randomBytes(24).toString('hex'),
  E2E_SESSION_SECRET: randomBytes(32).toString('hex'),
  E2E_PASSWORD: randomBytes(24).toString('hex'),
  E2E_TOTP_SECRET: base32(randomBytes(20)),
};
const composeArgs = ['compose', '--env-file', envFile, '-f', 'tests/e2e/compose.yml', '-p', project];
function compose(args, capture = false) {
  const result = spawnSync('docker', [...composeArgs, ...args], {
    cwd: root, env, encoding: 'utf8', stdio: capture ? 'pipe' : 'inherit', maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) throw new Error(`Docker test operation failed: ${args[0]}`);
  return result.stdout?.trim();
}

let exitCode = 1;
try {
  console.log(`Starting disposable UI test stack ${project}; existing dev services are not reused.`);
  if (candidate) compose(['pull', 'app']);
  compose(['up', candidate ? '--no-build' : '--build', '--detach', '--wait', '--wait-timeout', '180']);
  const migrations = fs.readdirSync(path.join(root, 'cmd/server/migrations'))
    .filter(name => /^\d+_.+\.up\.sql$/.test(name))
    .map(name => Number(name.split('_')[0]));
  if (!migrations.length) throw new Error('No source migrations found for candidate validation.');
  const schema = compose(['exec', '-T', 'postgres', 'psql', '-U', 'e2e', '-d', 'blocklist_e2e',
    '-Atc', 'SELECT version, dirty FROM schema_migrations'], true);
  if (schema !== `${Math.max(...migrations)}|f`) {
    throw new Error('The test image did not apply every source migration cleanly.');
  }
  const address = compose(['port', 'app', '5000'], true);
  if (!/^127\.0\.0\.1:\d+$/.test(address)) throw new Error('Test app must be published on loopback only.');
  env.E2E_BASE_URL = 'http://' + address;
  const browserAddress = compose(['port', 'browser', '3000'], true);
  if (!/^127\.0\.0\.1:\d+$/.test(browserAddress)) throw new Error('Test browser must be published on loopback only.');
  env.E2E_BROWSER_WS_ENDPOINT = 'ws://' + browserAddress + '/';
  const result = spawnSync(process.execPath, [require.resolve('@playwright/test/cli'), 'test', ...process.argv.slice(2)], {
    cwd: root, env, stdio: 'inherit',
  });
  exitCode = result.status ?? 1;
} catch (error) {
  console.error(error.message);
} finally {
  // This project name was randomly generated here, never supplied by the caller.
  try { compose(['down', '--volumes', '--remove-orphans']); }
  catch (error) { console.error(`Cleanup failed for ${project}: ${error.message}`); exitCode = 1; }
  if (path.dirname(authDir) === os.tmpdir() && path.basename(authDir).startsWith('blocklist-e2e-')) {
    fs.rmSync(authDir, {recursive: true, force: true});
  }
}
process.exitCode = exitCode;
