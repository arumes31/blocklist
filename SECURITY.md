# Security policy

## Supported versions

Security fixes are provided for the latest release and the current default branch.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **Security** tab by opening a
private vulnerability report. Do not open a public issue with exploit details or
credentials. Include affected versions, reproduction steps, impact, and any suggested
mitigation.

You should receive an acknowledgement within five business days. We will coordinate
validation, remediation, release timing, and responsible disclosure with the reporter.

## Security advisories for operators

- **Default GUIAdmin TOTP secret (builds from 2026-01-31 to 2026-02-01).** Commit
  `b596da9` seeded the `GUIAdmin` recovery account with a fixed, publicly known TOTP
  secret whenever `GUIToken` was empty; `d6c687a` removed it the next day. A database
  first seeded by an affected build keeps that secret, because seeding never runs again
  for an existing account. If yours may have been, clear the enrollment
  (`UPDATE admins SET token = '', session_version = session_version + 1 WHERE username = '<GUIAdmin>';`),
  sign in to enroll a new authenticator, and review the audit log for unexpected
  GUIAdmin sign-ins.
