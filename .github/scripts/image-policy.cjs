const {execFileSync} = require('node:child_process');

function validateProductionPolicy(environment, policies, currentSHA, candidateSHA) {
  const reviewed = environment.protection_rules?.some(rule =>
    rule.type === 'required_reviewers' && rule.reviewers?.length > 0);
  if (!reviewed) throw new Error('production must have required reviewers.');
  if (environment.can_admins_bypass !== false) throw new Error('Disable administrator bypass for production.');
  if (environment.deployment_branch_policy?.custom_branch_policies !== true ||
      policies.total_count !== 1 || policies.branch_policies?.length !== 1 ||
      policies.branch_policies[0].name !== 'main' || policies.branch_policies[0].type !== 'branch') {
    throw new Error('Restrict production to the main branch only (no tags or wildcards).');
  }
  if (!/^[a-f0-9]{40}$/.test(candidateSHA || '') || currentSHA !== candidateSHA) {
    throw new Error('Candidate is no longer the main head. Review a fresh tested run; do not promote stale candidates.');
  }
}

if (require.main === module) {
  try {
    if (process.env.GITHUB_REF !== 'refs/heads/main') throw new Error('Production promotion requires main.');
    const repo = process.env.GITHUB_REPOSITORY;
    if (!/^[\w.-]+\/[\w.-]+$/.test(repo || '')) throw new Error('Invalid repository.');
    const get = suffix => JSON.parse(execFileSync('gh', ['api', `repos/${repo}/${suffix}`], {encoding: 'utf8'}));
    validateProductionPolicy(get('environments/production'),
      get('environments/production/deployment-branch-policies?per_page=100'),
      get('git/ref/heads/main').object.sha, process.env.GITHUB_SHA);
    console.log('Production approval configuration and candidate revision verified.');
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
module.exports = {validateProductionPolicy};
