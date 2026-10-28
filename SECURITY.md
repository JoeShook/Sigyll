# Security Policy

Sigyll is a Certificate Authority. A weakness in it can let someone obtain a certificate they shouldn't, use a key
they shouldn't, or hide what they did, so security reports get priority over everything else.

## Reporting a vulnerability

Please report privately. Don't open a public issue or pull request for a vulnerability.

- **Preferred:** GitHub's private vulnerability reporting. Use **Report a vulnerability** on this repository's
  [Security tab](https://github.com/JoeShook/Sigyll/security).
- **Or email:** Joe Shook, joeshook@gmail.com.

Include what you found, how to reproduce it, and the commit or version you tested. You'll get an acknowledgement
within three business days and a plan for a fix once it's confirmed. Fixes are released before details are made
public, and reporters are credited unless they ask not to be.

## Supported versions

Sigyll is developed on `main`, and fixes land there. There are no long-term release branches yet.

## In scope

The CA (`Sigyll`, `Sigyll.Common`, `Sigyll.UI`), the RA portal (`Sigyll.Portal`), the certificate server, the
signing providers, the Flyway schema and the container images. Weaknesses in third-party dependencies are welcome
too, though the fix may belong upstream.

## How Sigyll is secured

- [Security architecture](Sigyll/docs/SECURITY-ARCHITECTURE.md): key protection, roles, the audit trail,
  lifecycle integrity and hardening.
- [Audit readiness](Sigyll/docs/AUDIT-READINESS.md): the controls CA audits examine, what is in place, and what
  is still to be built.
