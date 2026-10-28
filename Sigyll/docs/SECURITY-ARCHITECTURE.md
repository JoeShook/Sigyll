# Sigyll Security Architecture

Sigyll is a Certificate Authority (CA) with a separate Registration Authority (RA). This page describes how it
protects the things a CA exists to protect: its signing keys, the integrity of what it issues and revokes, and
the record of who did what. For how these controls line up with the criteria CA audits use, see
[AUDIT-READINESS.md](AUDIT-READINESS.md). To report a vulnerability, see [SECURITY.md](../../SECURITY.md).

## Components

```
                 requesters                                  relying parties
                     |                                              |
                     v                                              v
   +------------------------------+                  +---------------------------+
   |  Sigyll.Portal  (RA)         |                  | Sigyll.Certificate.Server |
   |  passkey sign-in, requests,  |                  | static AIA certs and CRLs |
   |  domain validation, RA queue |                  | GET/HEAD only, no listing |
   |  holds no CA keys            |                  +---------------------------+
   +------------------------------+                                ^
                     | RA API (mTLS or API key)                     | publishes
                     v                                              |
   +-------------------------------------------------------------------------+
   |  Sigyll  (CA)  - operator UI, issuance, revocation, CRLs, audit trail   |
   |  operators sign in (password + authenticator app, or passkey); roles    |
   +-------------------------------------------------------------------------+
          |                         |                           |
          v                         v                           v
   +-------------+      +------------------------+     +-------------------+
   | PostgreSQL  |      | Signing providers      |     | HashiCorp Vault   |
   | CA state,   |      | local keys, Vault      |     | Transit keys, KV  |
   | audit trail |      | Transit, GCP Cloud KMS |     | master key, KV    |
   | (Flyway)    |      +------------------------+     | certificate export|
   +-------------+                                     +-------------------+
```

| Component | Role | Trust |
|---|---|---|
| **Sigyll** (`Sigyll`, `Sigyll.Common`, `Sigyll.UI`) | The CA: operator UI, issuance, renewal, revocation, CRL generation, audit trail | Holds or controls the CA signing keys; operators only |
| **Sigyll.Portal** | The RA: requester accounts, certificate requests, http-01 domain validation, RA approval queue | Never holds CA keys; asks the CA to sign through the RA API |
| **Sigyll.Certificate.Server** | Publishes CA certificates (AIA) and CRLs (CDP) | Public, read-only |
| **Signing providers** (`Sigyll.Vault`, `Sigyll.Gcp`) | Sign certificates and CRLs with keys held outside the application | Keys never leave Vault Transit or Cloud KMS |
| **PostgreSQL** | CA state and the audit trail | Schema owned by Flyway migrations, not the application |

## Separation of duties

**CA and RA are separate applications.** The RA vets requesters and requests; only the CA signs. The RA reaches
the CA through two endpoints, `GET /api/ra/catalog` and `POST /api/ra/issue`, and acts as a system identity
that holds a single permission, `IssueFromRa`: it can ask for CSR-based issuance and nothing else.

**Operators hold roles, and roles map to permissions in one place** (`Sigyll.Common/Security/SigyllRoles.cs`):

| Role | Permissions | Intent |
|---|---|---|
| Auditor | View | Read everything, change nothing |
| CaOperator | View, Operate | Issue, renew, revoke, import, publish CRLs, run jobs |
| Admin | View, Operate, Administer | Configuration, trust domains, profiles, operators, destructive actions |
| KeyCustodian | View, ExportKeys | Export private keys; Admin does **not** include this |

**Every service call checks the caller.** Each public method on a service that touches the CA database demands a
permission, or carries an attribute stating why it needs none. A test (`ServiceBoundaryTests`) fails the build if
a new method does neither, so a page or endpoint can't reach CA data by forgetting a check.

## Key protection

| Where the key lives | How it is protected |
|---|---|
| **HashiCorp Vault Transit** | The CA key is generated in Vault and never leaves it; Sigyll sends a digest and gets a signature back |
| **Google Cloud KMS** | Same model, with Cloud KMS keys. Sigyll creates them at the software protection level today; HSM-backed keys are on the roadmap ([AUDIT-READINESS.md](AUDIT-READINESS.md)) |
| **Local (PKCS #12 in the database)** | Each key's password is wrapped with a 256-bit master key (AES-GCM envelope encryption). The master key is read at startup from Vault KV through an AppRole with a read-only policy; it is never stored in the database or in configuration |

Keys signed remotely can't be exported at all. Exporting a local private key requires the KeyCustodian role, and
the export is written to the audit trail *before* the key is released: if the audit record can't be stored, the
key isn't returned.

## Operator authentication

Operators sign in with ASP.NET Core Identity: a password plus an authenticator app (TOTP), or a passkey
(WebAuthn/FIDO2). The CA has no self-registration; an Admin creates operator accounts, and a role change rotates
the operator's security stamp so open sessions pick it up. Download endpoints that return private keys require the
KeyCustodian policy.

## Audit trail

Every CA operation and operator change is recorded in the `AuditEvents` table: issuance (with success or failure),
import, revocation with its reason, deletion, archiving, moves, CRL generation and import, private-key export,
Vault writes, request lifecycle, trust-domain deletion, and operator creation, role changes, password resets and
deletion. Each record holds the actor, whether it was a person or a scheduled job, the target (type, id, name,
subject, thumbprint, trust domain) and a detail line.

The table is **append-only in the database**, not just in the application: a trigger stamps the time from the
database clock and rejects every UPDATE, DELETE and TRUNCATE, and where the deployment has a separate write role,
that role has those privileges revoked (`dist/AlloyDB/sigil/sigil/tables/V8__audit_trail.sql`). Records outlive the certificates they describe. Auditors
read them on the Audit Trail page, filtered by action, actor or certificate.

## Certificate lifecycle integrity

- **Revocation** records the RFC 5280 reason code, regenerates the issuing CA's CRL, and keeps the serial in
  `CertificateRevocations`.
- **CRLs** carry monotonically increasing CRL numbers and are renewed by a scheduled job before `nextUpdate`.
- **Archive** retires a certificate and keeps it; hard delete is limited to Admins and recorded with whether Sigyll
  held its private key and where a remote key lived.
- **Renewal lineage** (`Version`, `RenewalOfId`) is kept across re-key and re-sign, and is only recorded when the
  subject is unchanged.

## Publication

The certificate server publishes only `.cer`, `.crt`, `.crl`, `.p7c` and `.pem` files with their RFC 2585 media
types, accepts only GET and HEAD, and has no directory listing. Relying parties fetch the exact AIA and CDP URLs
written into each certificate.

## Platform and web hardening

- **Containers** run as an unprivileged user (uid 1654), from base images pinned by digest.
- **Browser responses** carry `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, a same-origin referrer and
  opener policy, a Permissions-Policy that disables camera, microphone, location, payment and USB, and HSTS for a
  year outside Development. Requests are redirected to HTTPS.
- **Content Security Policy** allows only the application's own scripts (`script-src 'self'`). The CA enforces it;
  the RA portal runs it report-only until its pages are checked. Violations are logged either way; each app's
  `SecurityHeaders:EnforceContentSecurityPolicy` setting picks the mode.
- **Errors** outside Development show a generic page with a request ID; exception details stay in the log.

## Secure development

Every push and pull request runs ([`.github/workflows`](../../.github/workflows)):

| Check | What it does |
|---|---|
| Build and test | Release build and the full test suite on Linux |
| Vulnerable packages | Fails on any direct or transitive NuGet package with a published advisory |
| CodeQL | Static analysis of the C# code with the security-extended queries; also weekly |
| Container scan | Builds the image, fails if it runs as root, and scans it with [Grype](https://github.com/anchore/grype); fails on high or critical vulnerabilities that have a fix |
| SBOM | A CycloneDX software bill of materials for each deployable application |
| SQL style | Every schema migration follows the Flyway style rules |

Every GitHub Action is pinned to a commit, workflow tokens are read-only except where CodeQL uploads results, and
Dependabot proposes
updates to NuGet packages, the Actions and the container base images every week.
