# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in the **Sigyll** repository.

## Project Overview

**Sigyll** is a modern, .NET-native Certificate Authority (CA) and PKI management platform with first-class UDAP/FHIR support — a lightweight, developer-friendly alternative to EJBCA. It provides a Blazor web UI for creating, importing, and managing X.509 certificate hierarchies, CRLs, DIDs, and Verifiable Credentials, with local or remote (HashiCorp Vault Transit, GCP KMS) signing.

- **Repository**: https://github.com/JoeShook/Sigyll
- **Maintainer**: Joe Shook (joeshook@gmail.com)
- **Heritage**: Extracted from `JoeShook/udap-dotnet` (`examples/CA/`, then named **Sigil**) on 2026-06-07 with full git history preserved, then renamed Sigil → Sigyll. See memory `sigyll-extraction` for the case-sensitive rename gotchas.

## Stack
- .NET 10, Blazor Server (InteractiveServer), Microsoft FluentUI v4
- PostgreSQL (Npgsql + EF Core), BouncyCastle, Serilog, Hangfire
- .NET Aspire orchestration (AppHost) + HashiCorp Vault (Transit signing)

## Solution layout (`Sigyll.slnx`)
- **Sigyll** — Blazor Server host (Program.cs, DI, config, download API)
- **Sigyll.Common** — entities, EF Core (`SigyllDbContext`), services, ViewModels (no UI deps)
- **Sigyll.UI** — Razor Class Library (all Blazor components/pages)
- **Sigyll.Did / Sigyll.Vc** — DID documents + Verifiable Credential issuance/verification
- **Sigyll.Vault / Sigyll.Vault.Hosting** — Vault Transit signing + Aspire hosting integration
- **Sigyll.Gcp** — GCP KMS signing + publishing
- **Sigyll.FileSystem** — filesystem CRL/cert publishing
- **Sigyll.Certificate.Server** — static host for CRLs/certs
- **Sigyll.AppHost / Sigyll.ServiceDefaults** — Aspire orchestrator + defaults
- **_tests/Sigyll.Signing.Tests** — xUnit + Shouldly

## Build / Run / Test
```bash
dotnet build Sigyll.slnx

# Full stack via Aspire (Vault + Sigyll + cert server) — opens an Aspire dashboard
dotnet run --project Sigyll.AppHost/Sigyll.AppHost.csproj

# Standalone app (local signing, no Vault) — https://localhost:7200
dotnet run --project Sigyll

# Tests — use Shouldly, NOT FluentAssertions (see Conventions)
dotnet test _tests/Sigyll.Signing.Tests

# EF migrations
dotnet ef database update --project Sigyll.Common --startup-project Sigyll
```

## Database
PostgreSQL on localhost. Connection in `Sigyll/appsettings.json` (key **`SigyllDb`**):
`Host=localhost;Database=sigil;Username=sigil;Password=sigil_pass;Search Path=sigil`
The DB/user/schema name is lowercase **`sigil`** (see Conventions → case-sensitive heritage). EF applies migrations on startup.

## Current focus — Phase 12 (see `ROADMAP.md`)
**Certificate Request Portal & ACME Automation**, sequenced **portal-first**:
- **12a Portal** — ASP.NET Core Identity (.NET 10) **passkeys** (WebAuthn/FIDO2) for auth, plus a *separate* **identity-proofing** layer (Persona/Stripe Identity/Onfido/ID.me for individuals; domain + business validation for orgs) and an RA approval workflow.
- **12b ACME server (RFC 8555)** — directory/nonce/account/order/challenge/finalize, revocation, **EAB (RFC 8555 §7.3.4)**, **ARI (RFC 9773)**, ACME profiles (`draft-ietf-acme-profiles`).
- **Key decision**: passkeys are *authentication only*; the **RA/proofing gate mints the EAB credential** that lets ACME automate issuance/renewal for already-vetted accounts. UDAP server certs fit ACME domain-validation; UDAP client certs need EAB on top of portal vetting. No standardized ACME-for-UDAP profile exists yet.

## Conventions & gotchas (learned the hard way)
- **Tests: use Shouldly (MIT), never FluentAssertions** — FA v8 is paid for commercial use, and this code is used in a for-profit solution.
- **Case-sensitive heritage**: the Sigil→Sigyll rename replaced capital `Sigil` only. Lowercase `sigil` was preserved on purpose because it ties to persisted/external state — do NOT blindly "fix" these:
  - PostgreSQL DB/user/schema name `sigil`
  - Vault transit key names `sigil-rsa-4096`, `sigil-ecdsa-p384`
  - JS helper `window.sigilFreezeResizableGrids`, attribute `data-sigil-frozen`
- **Vault (Aspire)**: persistent init state at `%LOCALAPPDATA%/Sigyll/vault-vault-init.json`; data in Docker volume **`vault-vault-data`** — never `docker volume rm` it. Stop the app via Ctrl+C / the Aspire dashboard so Aspire removes the `vault-vault` container cleanly; if it orphans, `docker rm -f vault-vault` (container only).
- **Hangfire**: recurring/queued jobs persist fully-qualified type names in the DB, so renames break stored jobs. `Sigyll/Program.cs` re-registers the CRL job when its persisted definition has a `LoadException` (preserving cron) — keep this pattern.
- **FluentUI v4 DataGrid**: resize handles on minmax/fr/auto tracks are dead until the first drag — `window.sigilFreezeResizableGrids()` (`Sigyll/Components/App.razor`) freezes tracks to px at init. Use `Class="multiline-text"` for wrapping cells. The v4 handle class is `.actual-resize-handle` (NOT v3's `.col-width-draghandle`).
- **Line endings**: working tree is LF (global git `autocrlf=true`). Prefer the Edit tool / `perl -i` for in-place edits; avoid tools that strip line endings.
- **Git identity / push**: commits are authored `Joe Shook <joeshook@gmail.com>`. Push via **GitHub Desktop** (the `JoeShook` GitHub account) — the machine's active `gh` account is a different org account without write access here.

## Relationship to udap-dotnet
Sigyll has **no code dependency** on the udap-dotnet SDK today. When Phase 8 (UDAP/FHIR features) lands, consume the published `Udap.*` NuGet packages rather than project references.
