# Security Policy

## Supported versions

Only the latest published version receives security fixes.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report vulnerabilities privately by emailing the repository
maintainers or using GitHub's private security advisory feature:
<https://github.com/bnomei/towershield/security/advisories/new>

Include:

- A description of the vulnerability.
- Steps to reproduce or a proof-of-concept (if safe to share).
- Affected versions.
- Any suggested fix.

We aim to acknowledge reports within 72 hours and publish a fix or advisory
within 30 days.

## Scope

This library is a path-denylist middleware. Please report:

- Bypass techniques that allow a matched scanner path to reach the inner
  service.
- Incorrect percent-encoding behaviour that enables a bypass.
- Unsafe code introduced by a dependency.

Out of scope:

- False positives (paths incorrectly blocked) – these are bugs, not security
  vulnerabilities; please open a regular issue.
- Requests for new rules – please open a regular issue or pull request.
