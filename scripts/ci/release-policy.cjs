'use strict';

const assert = require('node:assert/strict');

function validateProduction(environment, branches) {
  assert.equal(environment.can_admins_bypass, false, 'Disable administrator bypass for production');
  assert.ok(environment.protection_rules?.some(rule =>
    rule.type === 'required_reviewers' && rule.reviewers?.length > 0),
  'production must have at least one required reviewer');
  assert.deepEqual(environment.deployment_branch_policy,
    { protected_branches: false, custom_branch_policies: true },
    'production must use selected branches and tags');
  assert.equal(branches.length, 1, 'production must have exactly one deployment branch rule');
  assert.equal(branches[0].name, 'main');
  assert.equal(branches[0].type, 'branch', 'Tags and wildcards cannot deploy to production');
}

function publicationTags(ref, sha) {
  assert.match(sha, /^[a-f0-9]{40}$/);
  switch (ref) {
    case 'refs/heads/main': return ['main', 'latest', sha];
    default: throw new Error('This ref cannot publish images');
  }
}

async function github(path, method = 'GET') {
  const response = await fetch(`${process.env.GITHUB_API_URL || 'https://api.github.com'}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${process.env.GH_TOKEN}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });
  if (!response.ok) throw new Error(`GitHub ${method} ${path}: ${response.status}`);
  return response.status === 204 ? null : response.json();
}

async function checkProduction() {
  const base = `/repos/${process.env.GITHUB_REPOSITORY}/environments/production`;
  const environment = await github(base);
  const result = await github(`${base}/deployment-branch-policies?per_page=100`);
  assert.equal(result.total_count, 1, 'Unexpected deployment branch rules');
  validateProduction(environment, result.branch_policies);
}

module.exports = { validateProduction, publicationTags, github, checkProduction };
if (require.main === module) checkProduction().catch(error => { console.error(error.message); process.exitCode = 1; });
