'use strict';

const { github } = require('./release-policy.cjs');

function canDelete(version, now = Date.now()) {
  const tags = version.metadata?.container?.tags;
  // Retain untagged manifests: they may be platform images or attestations
  // referenced by a protected candidate/index, not unused packages.
  if (!Array.isArray(tags) || tags.length === 0) return false;
  if (tags.some(tag => /^(main|latest|test|v2_test|v2b_test|rollback)$/.test(tag) ||
    tag.startsWith('candidate-') || tag.startsWith('v'))) return false;
  return Date.parse(version.updated_at) < now - 30 * 24 * 60 * 60 * 1000;
}

async function cleanup() {
  const [owner, name] = process.env.GITHUB_REPOSITORY.split('/');
  const account = await github(`/users/${owner}`);
  const base = `/${account.type === 'Organization' ? 'orgs' : 'users'}/${owner}/packages/container/${encodeURIComponent(name.toLowerCase())}/versions`;
  const versions = [];
  for (let page = 1; ; page++) {
    const batch = await github(`${base}?per_page=100&page=${page}`);
    versions.push(...batch);
    if (batch.length < 100) break;
  }
  versions.sort((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at));
  const dryRun = process.env.DRY_RUN !== 'false';
  for (const version of versions.slice(10)) {
    if (!canDelete(version)) continue;
    // Re-read immediately before deleting to avoid acting on stale tags.
    const current = await github(`${base}/${version.id}`);
    if (!canDelete(current)) continue;
    console.log(`${dryRun ? 'Would delete' : 'Deleting'} version ${version.id}: ${current.metadata.container.tags.join(', ')}`);
    if (!dryRun) await github(`${base}/${version.id}`, 'DELETE');
  }
}

module.exports = { canDelete };
if (require.main === module) cleanup().catch(error => { console.error(error.message); process.exitCode = 1; });
