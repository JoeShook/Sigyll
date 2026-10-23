# Export to Vault KV — design handoff

Status: proposed (2026-10-23). Not started.

## Goal

Let a key custodian send a chosen set of certificates, with their private keys, from Sigyll straight into a
HashiCorp Vault KV v2 secret, instead of downloading each `.p12`/`.cer` one at a time and zipping them by hand.
Whoever consumes the certificates (a development environment, a test harness, a deployment) reads them from
Vault with their own Vault identity. After a renewal or re-sign, one re-export updates every consumer: there's no
new zip to hand around, and no shared zip password.

## Where it fits

- **Not an `IPublishingProvider`.** That interface publishes public artifacts (CRLs, certificates) to a
  location derived from a URL. This feature releases private keys, so it belongs beside
  `CertificateExportService` and follows the same rules as a `.p12` download.
- **New abstraction:** an export destination, e.g. `IKeyExportDestination`, in `Sigyll.Common/Services/Export/`,
  taking a built bundle (below) and returning where it went. First implementation: `VaultKvExportDestination` in
  `Sigyll.Vault`.
- **Its own Vault connection.** The destination Vault is usually not the Vault that does Transit signing (that
  one may be a local Aspire container). Use a separate options section, e.g. `VaultExport`: `Address`, `Mount`
  (default `secret`), `Namespace` (Enterprise), and auth by `Token` or AppRole (`RoleId`/`SecretId`), reusing the
  token-acquisition logic in `VaultTokenSource` where it fits. The token needs `create`/`update` on the target
  path only.

## Export sets

A saved, named selection, so a re-export is one click (or a job), not re-picking certificates:

- Name, trust domain, destination path (e.g. `team/certs/dev-bundle`).
- Entries: certificate (CA or issued), **file name** in the bundle (consumers address entries by it, so keep it
  stable across renewals), and kind: `p12`, `p12+chain` or `cer`.
- Renewal-aware: an entry should follow the certificate's lineage (`RenewalOfId` / the Phase 13 family id), so
  after a renewal the set exports the newest generation under the same file name.
- Persisted in new tables (Flyway V file under `dist/AlloyDB/sigil/...`, passing `tools/sql-lint/check_sql.py`).

## Secret layout (the consumer contract)

One KV v2 secret per export set, at `<mount>/data/<path>`:

| Field | Value |
|---|---|
| `<file name>` (one per entry) | base64 of the `.p12` or DER `.cer` |
| `_password` | the password of every `.p12` in this export: random, generated per export |
| `_manifest` | JSON: `exportedAt`, `exportedBy`, `sigyllVersion`, and per entry `file`, `kind`, `subject`, `thumbprint`, `notAfter`, `serial` |

- A random password per export means no shared password is ever written down or handed out. Consumers read it
  from the same secret, under the same Vault policy.
- KV v2 keeps versions, so a bad export rolls back with `vault kv rollback`.
- **Size:** Vault's integrated (Raft) storage caps an entry at about 1 MiB by default. Base64 adds a third.
  Refuse an export over ~768 KB with a message to split the set, rather than letting Vault reject it.
- Write the whole secret in one request, so consumers never see half an export.

## Rules (same as a download)

- `KeyCustodian` role only (Admin doesn't include it).
- Refuse entries whose key isn't exportable (`CertSecurityLevel != Software`); `cer` entries are always allowed.
- CA private keys: leave out of scope for the first version (CA certificates go as `cer` only). Revisit if a
  real need appears.
- Every export is a key-release event in the Phase 13 key-egress audit table: artifact kind `vault-kv`, one row
  per entry that carried key material, with destination = Vault address + path + resulting KV version. Unlike a
  download, the destination is actually known.

## UI

- An **Export sets** page: list, create/edit (pick certificates, set file names and kinds), and **Export to Vault**
  with the result (KV version, entry count, size).
- On a certificate's detail panel: which export sets include it, and when each last exported it.
- Optional: "re-export after renewal" per set, as an `IRecurringJobDefinition` or a hook on renewal, that
  exports when an entry's newest generation differs from the last exported thumbprint.

## Build order

1. Export-set tables (Flyway) + entities + `ExportSetService` (CRUD; resolve entries to newest generation).
2. Bundle builder in `Sigyll.Common`: produce `{file → bytes}`, the generated password, and the manifest, using
   `CertificateExportService` for the `.p12` bytes. Unit-test with Shouldly.
3. `IKeyExportDestination` + `VaultKvExportDestination` + `VaultExport` options. Integration-test against the
   AppHost's Vault container with a KV v2 mount enabled.
4. Audit rows (lands with, or stubs ahead of, Phase 13 item 2).
5. UI page + detail-panel links.
6. Optional re-export-after-renewal job.
7. A ROADMAP entry and a FEATURES.md section once it ships.

## Open questions

- Does `p12+chain` include the root, or stop at the issuing intermediate?
- Should a set be able to span trust domains?
- Read-back check after writing (read the secret and compare thumbprints) — worth the extra permission?
- Other destinations later (Azure Key Vault secrets, GCP Secret Manager) — keep the interface general enough.
