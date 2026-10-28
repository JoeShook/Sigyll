# Audit Readiness

Sigyll is built to run a Certificate Authority that can pass the audits CAs are held to. This page maps the
controls those audits examine to what Sigyll does today, with the evidence in this repository, and lists what is
still to be built. How the controls work is described in [SECURITY-ARCHITECTURE.md](SECURITY-ARCHITECTURE.md).

## What an audit certifies

CA audits such as **WebTrust for Certification Authorities** and **ETSI EN 319 411**, and healthcare trust
frameworks built on them such as **DirectTrust**, certify a CA *operator*: its software, people, procedures and
facilities together. No software is certified on its own. What software must do is enforce the technical controls
and produce the evidence an auditor asks for. That is Sigyll's job, and this page tracks it.

The criteria used below come from those audit schemes and from the standards they reference:

- WebTrust Principles and Criteria for Certification Authorities
- CA/Browser Forum Network and Certificate System Security Requirements
- NIST SP 800-57 (key management) and FIPS 140-3 (cryptographic modules)
- RFC 3647 (Certificate Policy and Certification Practice Statement framework) and RFC 5280 (certificates and CRLs)

## Status

**In place**: built, tested and in use. **Partial**: the core exists, with named gaps. **Planned**: not built yet.

| Control area | Status | What Sigyll does | Evidence |
|---|---|---|---|
| CA and RA separation | In place | The RA (Sigyll.Portal) vets requesters and never holds CA keys; the CA signs. The RA's identity can only request CSR-based issuance | `Sigyll/Program.cs` (RA API), `Sigyll.Portal` |
| Role-based access and least privilege | In place | Auditor, CaOperator, Admin and KeyCustodian roles; key export is its own role, outside Admin; every service method checks a permission, enforced by a test | `Sigyll.Common/Security/SigyllRoles.cs`, `ServiceBoundaryTests` |
| Audit logging of CA events | In place | Issuance, revocation, deletion, key export, CRL, Vault and operator events recorded with actor, target and outcome; append-only in the database; key export refused if the record can't be stored | `V8__audit_trail.sql`, `Sigyll.Common/Services/Audit`, `AuditTrailTests` |
| Revocation and CRLs | In place | RFC 5280 reason codes; CRL regenerated on revocation; increasing CRL numbers; scheduled renewal before `nextUpdate`; public CRL and AIA publication | `CrlGenerationService`, `CrlAutoRenewalJob`, `Sigyll.Certificate.Server` |
| Secure development lifecycle | In place | Build, tests, vulnerable-package gate, CodeQL, container scan and SBOM on every change; Actions pinned by commit; Dependabot | [`.github/workflows`](../../.github/workflows) |
| CA private key protection | Partial | Keys can be held in Vault Transit or Google Cloud KMS, where they never leave; local keys are encrypted with a master key held in Vault. **Gap:** FIPS 140-3 Level 3 HSM support (PKCS #11) and HSM-level Cloud KMS keys | `Sigyll.Vault`, `Sigyll.Gcp`, `KeyPasswordProtection.cs` |
| Operator authentication | Partial | No self-registration; passkeys and authenticator-app MFA available; role changes end open sessions. **Gap:** MFA required for every operator, account lockout, idle session timeout | `Sigyll/Components/Account` |
| Certificate content control | Partial | Certificate profiles fix key algorithm, extensions, key usage and SAN types; CSR proof of possession checked; DNS names must be domain-validated unless an RA approved the request. **Gap:** verify RA approval references, validate every SAN type | `CertificateIssuanceService`, `DomainValidationService` |
| Serial and lifecycle integrity | Partial | Archive instead of delete; renewal lineage kept; revocation history kept. **Gap:** revoke-before-delete, tombstones so no issued serial is ever forgotten, CA deletion blocked while unexpired certificates exist | [ROADMAP.md](../../ROADMAP.md) Phase 13 |
| System hardening | Partial | Non-root containers with pinned images; security headers, HSTS, HTTPS redirect; generic error pages; certificate server limited to GET of certificates and CRLs. **Gap:** content security policy enforced on the RA portal (enforced on the CA), RA API key rules and working mTLS, allow-lists for outbound fetches and publishing paths | `Sigyll.ServiceDefaults/SecurityHeaders.cs`, `Sigyll/Dockerfile` |
| Multi-person control | Planned | Two authorized people required for CA key generation, CA key export or destruction, and CA deletion | |
| Tamper-evident audit | Planned | Hash-chained audit records with periodic checkpoints signed by an HSM key; export for the auditor; retention policy | |
| Certificate status (OCSP) | Planned | RFC 6960 OCSP responder alongside CRLs | [ROADMAP.md](../../ROADMAP.md) Phase 7 |
| Policy and practice documents | Planned | A Certificate Policy and Certification Practice Statement in RFC 3647 form, key ceremony scripts, incident response and business continuity procedures | |

## Plan

The remaining work is sequenced so each step leaves Sigyll more defensible than the last.

1. **Secure foundation.** CI gates and container and web hardening are done. Still to do: enforce the content
   security policy; require MFA, with lockout and an idle timeout; fix the RA API's authentication; add outbound
   and publishing allow-lists.
2. **Keys under control.** HSM-backed CA keys through PKCS #11 (FIPS 140-3 Level 3), HSM-level Cloud KMS keys,
   multi-person control for key ceremonies, export and destruction.
3. **Nothing happens unseen.** A tamper-evident audit trail with signed checkpoints and auditor export; the
   lifecycle integrity work, so no issued serial can be lost.
4. **Ready for an auditor.** A Certificate Policy and Certification Practice Statement, key ceremony scripts,
   incident response and continuity procedures, and a readiness assessment against the WebTrust criteria.

This page is updated as each item lands.
