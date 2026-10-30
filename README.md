# Sigyll — .NET PKI Management Tool

Sigyll is a modern Certificate Authority (CA) and PKI management platform built with .NET. It provides a web-based UI for creating, importing, and managing X.509 certificate hierarchies with support for local and remote (HashiCorp Vault Transit) key storage.

Designed as a lightweight alternative to enterprise CA tools like EJBCA, Sigyll is suitable for development, testing, and production PKI workflows — with first-class support for [UDAP](https://www.udap.org/) (Unified Data Access Profiles) healthcare security.

## Built for audited PKI

Sigyll is a Certificate Authority with a separate Registration Authority, built to run a CA that can pass the
audits CAs are held to (WebTrust for CAs, ETSI EN 319 411, and healthcare frameworks such as DirectTrust).

- **CA and RA separation.** The RA portal vets requesters and never holds CA keys; only the CA signs.
- **Keys outside the application.** CA keys can live in HashiCorp Vault Transit or Google Cloud KMS and never leave
  them; locally held keys are encrypted with a master key kept in Vault.
- **Least privilege.** Auditor, CA Operator, Admin and Key Custodian roles; private-key export is its own role.
- **An append-only audit trail** of every issuance, revocation, key export and operator change, enforced by the
  database.
- **Secure development.** Every change is built, tested, scanned with CodeQL, checked for vulnerable packages and
  container vulnerabilities, and gets a software bill of materials.

| Read | For |
|---|---|
| [Security architecture](Sigyll/docs/SECURITY-ARCHITECTURE.md) | How Sigyll protects keys, issuance, revocation and the audit record |
| [Audit readiness](Sigyll/docs/AUDIT-READINESS.md) | The controls CA audits examine, what is in place, and the plan for the rest |
| [Security policy](SECURITY.md) | How to report a vulnerability |

## Features

- **Certificate Explorer** — Hierarchical tree view of Root CA > Intermediate CA > End-entity > CRL chains with detail panel, ASN.1 viewer, and chain validation
- **Certificate Issuance** — Generate Root CAs, Intermediate CAs, and end-entity certificates from configurable profiles (RSA, ECDSA, and post-quantum ML-DSA, SLH-DSA, composite ML-DSA, and ML-KEM)
- **Certificate Profiles** — Preset and custom profiles controlling key algorithm, extensions, key usage, EKU, CDP, AIA, SANs, and more (the standards' term, not "template" — see [docs/NAMING.md](Sigyll/docs/NAMING.md))
- **Import & Auto-Detection** — Drag-and-drop import of .pfx, .cer, .pem, .crl files with automatic role detection and chain matching
- **Chain Validation** — Offline and online validation with CRL checking, AIA issuer resolution, and CDP CRL fetching
- **Renewal** — Re-key (new key pair) and re-sign (same key, new validity) with in-place entity update to preserve child relationships
- **Remote Signing** — HashiCorp Vault Transit or Google Cloud KMS (private keys never leave them)
- **Hybrid Signing** — Issue end-entity certs with local PFX private keys signed by Vault-backed CAs
- **Revocation & CRLs** — RFC 5280 reason codes, CRL generation and scheduled renewal, public CRL and AIA publishing
- **Registration Authority** — Request portal with passkey sign-in, domain validation and an RA approval queue
- **Audit Trail** — Append-only record of every CA operation and operator change
- **Dashboard** — Trust domain health, expiring/expired certs, overdue CRLs, and deep-link navigation
- **Trust Domains** — Independent PKI hierarchies (communities, tenants, environments) — see [docs/NAMING.md](Sigyll/docs/NAMING.md)
- **Download API** — REST endpoints for .cer, .pfx, .pem, and .crl downloads, with key export limited to Key Custodians

See [FEATURES.md](Sigyll/docs/FEATURES.md) for the complete feature list and [ROADMAP.md](ROADMAP.md) for planned phases.

## Architecture

```
Sigyll/                       # The CA: Blazor Server host (Program.cs, DI, config, RA and download APIs)
Sigyll.Common/                # Entities, services, ViewModels (no UI dependencies)
│   ├── Data/Entities/        # TrustDomain, CaCertificate, IssuedCertificate, Crl, AuditEvent, ...
│   ├── Security/             # Roles, permissions and the operator context
│   ├── Services/             # Issuance, validation, parsing, import, CRL, audit trail, ASN.1
│   └── Services/Signing/     # ISigningProvider, LocalSigningProvider
Sigyll.UI/                    # Razor Class Library (all CA pages and components)
Sigyll.Portal/                # The RA: request portal, domain validation, RA approval queue
Sigyll.Certificate.Server/    # Lab tool: lists and serves published CA certificates and CRLs
Sigyll.Vault/                 # Vault Transit signing, AppRole login, KV export
Sigyll.Gcp/                   # Google Cloud KMS signing and publishing
Sigyll.Did/, Sigyll.Vc/       # DID documents and Verifiable Credentials
Sigyll.AppHost/               # .NET Aspire orchestrator (PostgreSQL, Flyway, Vault, apps)
Sigyll.ServiceDefaults/       # OpenTelemetry, health checks, security headers
dist/AlloyDB/                 # Flyway schema migrations
```

**Key design principle:** `Sigyll.Common` has zero UI dependencies and can be consumed by CLI tools, APIs, or test harnesses independently.

**Stack:** .NET 10, Blazor Server (InteractiveServer), FluentUI v4, PostgreSQL, BouncyCastle, Serilog

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- [PostgreSQL](https://www.postgresql.org/download/) (15+ recommended)
- [Docker](https://www.docker.com/) (Flyway migrations; Vault Transit via Aspire)

## Getting Started

With the Aspire AppHost (`dotnet run --project Sigyll.AppHost`), steps 1 and 2 happen for you: it runs
PostgreSQL in a persistent container, creates the databases and applies the schema before Sigyll starts. To
use a PostgreSQL container you already run for other projects, see
[Sharing a Postgres you already run](dist/AlloyDB/README.md#sharing-a-postgres-you-already-run).

### 1. Create the PostgreSQL Databases (standalone only)

```sql
CREATE USER sigil WITH PASSWORD 'sigil_pass';
CREATE DATABASE sigil OWNER sigil;
CREATE DATABASE portal OWNER sigil;
```

### 2. Apply the Schema (Flyway)

The schemas live in [`dist/AlloyDB`](dist/AlloyDB) as Flyway migrations; the apps never create tables.
The Aspire AppHost runs them automatically before the apps start. Without it:

```bash
docker run --rm -v "$PWD/dist/AlloyDB/sigil/sigil:/flyway/sql:ro" flyway/flyway:10 \
  -url=jdbc:postgresql://host.docker.internal:5432/sigil -user=sigil -password=sigil_pass \
  -schemas=sigil -defaultSchema=sigil -locations=filesystem:/flyway/sql migrate
```

See [`dist/AlloyDB/README.md`](dist/AlloyDB/README.md) for the SQL style rules, adding a migration, and
upgrading a database created by older (EF-migrated) builds.

### 3. Run Sigyll (Standalone)

```bash
dotnet run --project Sigyll
```

Sigyll will be available at **https://sigyll.dev.localhost:7200** (any `*.localhost` name reaches your own machine,
and the .NET development certificate covers `*.dev.localhost`).

All certificate signing uses local PFX-based keys by default.

### 4. Run with Aspire + Vault Transit (Optional)

To enable remote signing via HashiCorp Vault Transit:

```bash
dotnet run --project Sigyll.AppHost
```

This starts:
- **Vault** in dev mode (Docker container) with Transit engine and pre-configured signing keys
- **Sigyll** with `Signing.Provider=vault-transit` and Vault connection injected via environment variables

The Aspire dashboard provides observability for both services.

## Configuration

### appsettings.json

```json
{
  "ConnectionStrings": {
    "SigyllDb": "Host=localhost;Database=sigil;Username=sigil;Password=sigil_pass;Search Path=sigil"
  },
  "Signing": {
    "Provider": "local"
  }
}
```

### Vault Transit (via environment variables or appsettings)

When running via Aspire AppHost, these are set automatically:

| Variable | Description | Default |
|----------|-------------|---------|
| `Signing__Provider` | `local` or `vault-transit` | `local` |
| `Vault__Address` | Vault HTTP address | `http://localhost:8200` |
| `Vault__RoleId` / `Vault__SecretId` | AppRole credentials Sigyll logs in with | — |
| `Vault__MountPath` | Transit engine mount path | `transit` |
| `Vault__KeyProtectionPath` | KV v2 path of the key-password master key | — |

### Signing Modes

When Vault Transit is configured, the certificate issuance dialog offers a **Key Storage** selector:

| Mode | End-Entity Key | Signing Key | PFX Export |
|------|---------------|-------------|------------|
| **Local (PFX)** | Generated locally | Local CA or Vault CA | Yes |
| **Vault Transit** | Generated in Vault | Vault CA | No (key never leaves Vault) |

This enables a hybrid workflow: Vault-backed CAs can issue end-entity certificates with exportable local private keys.

## Quick Start Workflow

1. **Create a Trust Domain** — Go to the Trust Domains page and add a new PKI hierarchy
2. **Create a Root CA** — In Certificate Explorer, click "New Root CA", select a Root CA profile
3. **Create an Intermediate CA** — Select the Root CA, click "Issue Certificate", pick an Intermediate CA profile
4. **Issue End-Entity Certs** — Select the Intermediate CA, issue client or server certificates
5. **Download** — Use the download buttons for .cer, .pfx, or .pem files
6. **Validate** — Click "Revalidate" or "Validate Online" to verify chain integrity

## Project Dependencies

| Package | Purpose |
|---------|---------|
| Npgsql.EntityFrameworkCore.PostgreSQL | PostgreSQL provider |
| BouncyCastle.Cryptography 2.6.2 | X.509 operations, CRL generation, chain validation |
| Microsoft.FluentUI.AspNetCore.Components | Blazor UI component library |
| Serilog.AspNetCore | Structured logging |
| Aspire.Hosting (optional) | .NET Aspire orchestration |

## License

See [LICENSE](LICENSE).
