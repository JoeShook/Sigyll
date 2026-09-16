#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.ViewModels;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;

namespace Sigyll.Common.Services;

/// <summary>
/// Outbound CSRs for external CAs, with Sigyll holding the private key until the certificate
/// comes back. Create → download/copy the CSR → submit to the CA → Fulfill with the returned
/// certificate → the certificate lands in the trust domain with its key. Everything is also
/// exportable to files (CSR PEM, passphrase-encrypted PKCS#8 key) so nothing is locked in.
/// </summary>
public class ExternalCertificateRequestService
{
    private const string KeyUsageOid = "2.5.29.15";
    private const string ExtendedKeyUsageOid = "2.5.29.37";
    private const string BasicConstraintsOid = "2.5.29.19";
    private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";
    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

    internal static readonly JsonSerializerOptions SanJsonOptions = new()
    {
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly IDbContextFactory<SigyllDbContext> _dbFactory;
    private readonly ILogger<ExternalCertificateRequestService> _logger;
    private readonly Pkcs12BundleService _bundleService;
    private readonly CertificateParsingService _parsingService;
    private readonly CertificateImportService _importService;

    public ExternalCertificateRequestService(
        IDbContextFactory<SigyllDbContext> dbFactory,
        ILogger<ExternalCertificateRequestService> logger,
        Pkcs12BundleService bundleService,
        CertificateParsingService parsingService,
        CertificateImportService importService)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        _bundleService = bundleService;
        _parsingService = parsingService;
        _importService = importService;
    }

    // ------------------------------------------------------------------ create

    public async Task<ExternalCertificateRequestResult> CreateAsync(CreateExternalCertificateRequest request, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
            return ExternalCertificateRequestResult.Failure("A name is required.");
        if (string.IsNullOrWhiteSpace(request.SubjectDn))
            return ExternalCertificateRequestResult.Failure("A subject DN is required.");

        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var trustDomain = await db.TrustDomains.FindAsync([request.TrustDomainId], ct);
        if (trustDomain == null)
            return ExternalCertificateRequestResult.Failure("Trust domain not found.");

        // Optional model certificate — lineage and (for FromModeledCertificate) extension source
        X509Certificate2? model = null;
        if (request.ModeledOnCertificateId is int modelId && !string.IsNullOrEmpty(request.ModeledOnEntityType))
        {
            var pem = request.ModeledOnEntityType == "CaCertificate"
                ? (await db.CaCertificates.FindAsync([modelId], ct))?.X509CertificatePem
                : (await db.IssuedCertificates.FindAsync([modelId], ct))?.X509CertificatePem;
            if (string.IsNullOrWhiteSpace(pem))
                return ExternalCertificateRequestResult.Failure("The certificate to model on was not found.");
            model = X509Certificate2.CreateFromPem(pem);
        }
        else if (request.Profile == CsrExtensionProfile.FromModeledCertificate)
        {
            return ExternalCertificateRequestResult.Failure("Choose a certificate to model on, or pick a different extension profile.");
        }

        AsymmetricAlgorithm? key = null;
        try
        {
            if (!TryParseSubject(request.SubjectDn, out var subject, out var subjectError))
                return ExternalCertificateRequestResult.Failure(subjectError!);

            key = CsrGenerationService.CreateNewKey(request.KeyAlgorithm, request.KeySize);

            var built = BuildCsr(subject, request.SubjectAltNames, request.Profile, model, key);

            // Same posture as PfxPassword on certificates: a random password stored alongside
            var keyPassword = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var encryptedKeyPem = key.ExportEncryptedPkcs8PrivateKeyPem(keyPassword, KeyPbe);
            var (alg, size) = DescribeKey(key);

            var entity = new ExternalCertificateRequest
            {
                TrustDomainId = request.TrustDomainId,
                Name = request.Name.Trim(),
                SubjectDn = subject.Name,
                SubjectAltNamesJson = SerializeSans(request.SubjectAltNames),
                CsrPem = built.CsrPem,
                KeyAlgorithm = alg,
                KeySize = size,
                PublicKeyThumbprint = built.PublicKeyThumbprint,
                EncryptedPrivateKeyPem = encryptedKeyPem,
                KeyPassword = keyPassword,
                Profile = request.Profile,
                ExternalCaName = string.IsNullOrWhiteSpace(request.ExternalCaName) ? null : request.ExternalCaName.Trim(),
                Notes = string.IsNullOrWhiteSpace(request.Notes) ? null : request.Notes.Trim(),
                ModeledOnCertificateId = model != null ? request.ModeledOnCertificateId : null,
                ModeledOnEntityType = model != null ? request.ModeledOnEntityType : null,
                Status = ExternalRequestStatus.Pending,
                CreatedAt = DateTime.UtcNow
            };

            db.ExternalCertificateRequests.Add(entity);
            await db.SaveChangesAsync(ct);

            _logger.LogInformation(
                "Created external CA request '{Name}' (ID {Id}) in trust domain {TrustDomainId}: {Alg} {Size}, profile {Profile}",
                entity.Name, entity.Id, entity.TrustDomainId, alg, size, request.Profile);

            return new ExternalCertificateRequestResult
            {
                Success = true,
                RequestId = entity.Id,
                CsrPem = built.CsrPem,
                PublicKeyThumbprint = built.PublicKeyThumbprint
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create external CA request '{Name}'", request.Name);
            return ExternalCertificateRequestResult.Failure($"Could not create the request: {ex.Message}");
        }
        finally
        {
            key?.Dispose();
            model?.Dispose();
        }
    }

    // ------------------------------------------------------------------ update

    /// <summary>
    /// Edits a pending request and regenerates its CSR. By default the stored key is reused, so
    /// the public key (and anything the CA may already have validated about it) stays the same;
    /// set <see cref="UpdateExternalCertificateRequest.RegenerateKey"/> to rotate it.
    /// </summary>
    public async Task<ExternalCertificateRequestResult> UpdateAsync(UpdateExternalCertificateRequest request, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
            return ExternalCertificateRequestResult.Failure("A name is required.");
        if (string.IsNullOrWhiteSpace(request.SubjectDn))
            return ExternalCertificateRequestResult.Failure("A subject DN is required.");

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var row = await db.ExternalCertificateRequests.FindAsync([request.Id], ct);
        if (row == null)
            return ExternalCertificateRequestResult.Failure("Request not found.");
        if (row.Status != ExternalRequestStatus.Pending)
            return ExternalCertificateRequestResult.Failure("Only pending requests can be edited.");

        X509Certificate2? model = null;
        if (row.ModeledOnCertificateId is int modelId && !string.IsNullOrEmpty(row.ModeledOnEntityType))
        {
            var pem = row.ModeledOnEntityType == "CaCertificate"
                ? (await db.CaCertificates.FindAsync([modelId], ct))?.X509CertificatePem
                : (await db.IssuedCertificates.FindAsync([modelId], ct))?.X509CertificatePem;
            if (!string.IsNullOrWhiteSpace(pem))
                model = X509Certificate2.CreateFromPem(pem);
        }
        if (request.Profile == CsrExtensionProfile.FromModeledCertificate && model == null)
            return ExternalCertificateRequestResult.Failure("This request has no modeled certificate to copy extensions from; pick a different profile.");

        AsymmetricAlgorithm? key = null;
        try
        {
            if (!TryParseSubject(request.SubjectDn, out var subject, out var subjectError))
                return ExternalCertificateRequestResult.Failure(subjectError!);

            key = request.RegenerateKey
                ? CsrGenerationService.CreateNewKey(request.KeyAlgorithm, request.KeySize)
                : LoadKey(row);

            var built = BuildCsr(subject, request.SubjectAltNames, request.Profile, model, key);

            if (request.RegenerateKey)
            {
                var keyPassword = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
                row.EncryptedPrivateKeyPem = key.ExportEncryptedPkcs8PrivateKeyPem(keyPassword, KeyPbe);
                row.KeyPassword = keyPassword;
                (row.KeyAlgorithm, row.KeySize) = DescribeKey(key);
            }

            row.Name = request.Name.Trim();
            row.SubjectDn = subject.Name;
            row.SubjectAltNamesJson = SerializeSans(request.SubjectAltNames);
            row.CsrPem = built.CsrPem;
            row.PublicKeyThumbprint = built.PublicKeyThumbprint;
            row.Profile = request.Profile;
            row.ExternalCaName = string.IsNullOrWhiteSpace(request.ExternalCaName) ? null : request.ExternalCaName.Trim();
            row.Notes = string.IsNullOrWhiteSpace(request.Notes) ? null : request.Notes.Trim();
            row.UpdatedAt = DateTime.UtcNow;

            await db.SaveChangesAsync(ct);

            _logger.LogInformation(
                "Updated external CA request '{Name}' (ID {Id}); CSR regenerated{KeyNote}",
                row.Name, row.Id, request.RegenerateKey ? " with a new key pair" : " with the existing key");

            return new ExternalCertificateRequestResult
            {
                Success = true,
                RequestId = row.Id,
                CsrPem = built.CsrPem,
                PublicKeyThumbprint = built.PublicKeyThumbprint
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update external CA request {Id}", request.Id);
            return ExternalCertificateRequestResult.Failure($"Could not update the request: {ex.Message}");
        }
        finally
        {
            key?.Dispose();
            model?.Dispose();
        }
    }

    // ------------------------------------------------------------------ CSR construction

    private static readonly PbeParameters KeyPbe = new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);

    private static bool TryParseSubject(string subjectDn, out X500DistinguishedName subject, out string? error)
    {
        try
        {
            subject = new X500DistinguishedName(subjectDn.Trim());
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            subject = null!;
            error = $"Subject DN is not valid: {ex.Message}";
            return false;
        }
    }

    private static (string CsrPem, string PublicKeyThumbprint) BuildCsr(
        X500DistinguishedName subject,
        List<SanEntry> sans,
        CsrExtensionProfile profile,
        X509Certificate2? model,
        AsymmetricAlgorithm key)
    {
        var csr = key switch
        {
            RSA rsa => new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ecdsa => new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256),
            _ => throw new InvalidOperationException("Unsupported key algorithm.")
        };

        var sanExtension = SanExtensionBuilder.Build(sans);
        if (sanExtension != null)
            csr.CertificateExtensions.Add(sanExtension);

        foreach (var ext in BuildProfileExtensions(profile, model))
            csr.CertificateExtensions.Add(ext);

        var csrPem = csr.CreateSigningRequestPem();
        var thumbprint = Convert.ToHexString(SHA256.HashData(csr.PublicKey.ExportSubjectPublicKeyInfo()));
        return (csrPem, thumbprint);
    }

    private static (string Algorithm, int Size) DescribeKey(AsymmetricAlgorithm key) => key switch
    {
        RSA r => ("RSA", r.KeySize),
        ECDsa e => ("ECDSA", e.KeySize),
        _ => ("Unknown", 0)
    };

    private static string? SerializeSans(List<SanEntry> sans)
    {
        var kept = sans.Where(s => !string.IsNullOrWhiteSpace(s.Value)).ToList();
        return kept.Count > 0 ? JsonSerializer.Serialize(kept, SanJsonOptions) : null;
    }

    private static IEnumerable<X509Extension> BuildProfileExtensions(CsrExtensionProfile profile, X509Certificate2? model)
    {
        switch (profile)
        {
            case CsrExtensionProfile.UdapClient:
                yield return new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true);
                yield return new X509EnhancedKeyUsageExtension([new Oid(ClientAuthOid)], false);
                break;

            case CsrExtensionProfile.TlsServer:
                yield return new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true);
                yield return new X509EnhancedKeyUsageExtension([new Oid(ServerAuthOid)], false);
                break;

            case CsrExtensionProfile.TlsServerAndClient:
                yield return new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true);
                yield return new X509EnhancedKeyUsageExtension([new Oid(ServerAuthOid), new Oid(ClientAuthOid)], false);
                break;

            case CsrExtensionProfile.FromModeledCertificate when model != null:
                foreach (var oid in new[] { KeyUsageOid, ExtendedKeyUsageOid, BasicConstraintsOid })
                {
                    var ext = model.Extensions[oid];
                    if (ext != null)
                        yield return new X509Extension(ext.Oid!, ext.RawData, ext.Critical);
                }
                break;
        }
    }

    // ------------------------------------------------------------------ query

    public async Task<List<ExternalCertificateRequestSummary>> ListAsync(int? trustDomainId, bool includeCompleted, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        var query = db.ExternalCertificateRequests.Include(r => r.TrustDomain).AsQueryable();
        if (trustDomainId is int td) query = query.Where(r => r.TrustDomainId == td);
        if (!includeCompleted) query = query.Where(r => r.Status == ExternalRequestStatus.Pending);

        var rows = await query.OrderByDescending(r => r.CreatedAt).ToListAsync(ct);
        return rows.Select(ToSummary).ToList();
    }

    public async Task<ExternalCertificateRequestSummary?> GetAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var row = await db.ExternalCertificateRequests.Include(r => r.TrustDomain).FirstOrDefaultAsync(r => r.Id == id, ct);
        return row == null ? null : ToSummary(row);
    }

    private static ExternalCertificateRequestSummary ToSummary(ExternalCertificateRequest r) => new()
    {
        Id = r.Id,
        TrustDomainId = r.TrustDomainId,
        TrustDomainName = r.TrustDomain?.Name ?? string.Empty,
        Name = r.Name,
        SubjectDn = r.SubjectDn,
        SubjectAltNames = ParseSans(r.SubjectAltNamesJson),
        KeyAlgorithm = r.KeyAlgorithm,
        KeySize = r.KeySize,
        PublicKeyThumbprint = r.PublicKeyThumbprint,
        Profile = r.Profile,
        Status = r.Status,
        CreatedAt = r.CreatedAt,
        UpdatedAt = r.UpdatedAt,
        FulfilledAt = r.FulfilledAt,
        ExternalCaName = r.ExternalCaName,
        Notes = r.Notes,
        ModeledOnCertificateId = r.ModeledOnCertificateId,
        ModeledOnEntityType = r.ModeledOnEntityType,
        FulfilledCertificateId = r.FulfilledCertificateId,
        FulfilledEntityType = r.FulfilledEntityType,
        FulfilledThumbprint = r.FulfilledThumbprint
    };

    internal static List<SanEntry> ParseSans(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try { return JsonSerializer.Deserialize<List<SanEntry>>(json, SanJsonOptions) ?? []; }
        catch { return []; }
    }

    // ------------------------------------------------------------------ export

    public async Task<ExternalRequestExportResult> ExportCsrAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var row = await db.ExternalCertificateRequests.FindAsync([id], ct);
        if (row == null) return ExternalRequestExportResult.Failure("Request not found.");

        return new ExternalRequestExportResult
        {
            Success = true,
            Content = row.CsrPem,
            FileName = SanitizeFileName(row.Name) + ".csr",
            ContentType = "application/pkcs10"
        };
    }

    /// <summary>
    /// Exports the private key as PKCS#8 PEM re-encrypted under an operator-chosen passphrase,
    /// so the stored random password never leaves Sigyll.
    /// </summary>
    public async Task<ExternalRequestExportResult> ExportPrivateKeyAsync(int id, string passphrase, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(passphrase))
            return ExternalRequestExportResult.Failure("A passphrase is required to export the private key.");

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var row = await db.ExternalCertificateRequests.FindAsync([id], ct);
        if (row == null) return ExternalRequestExportResult.Failure("Request not found.");

        try
        {
            using var key = LoadKey(row);
            var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);
            var pem = key.ExportEncryptedPkcs8PrivateKeyPem(passphrase, pbe);

            _logger.LogWarning("Private key of external CA request '{Name}' (ID {Id}) exported", row.Name, row.Id);

            return new ExternalRequestExportResult
            {
                Success = true,
                Content = pem,
                FileName = SanitizeFileName(row.Name) + ".key",
                ContentType = "application/x-pem-file"
            };
        }
        catch (Exception ex)
        {
            return ExternalRequestExportResult.Failure($"Could not export the private key: {ex.Message}");
        }
    }

    /// <summary>
    /// Exports the fulfilled certificate and its private key as a PKCS#12 protected by an
    /// operator-chosen password. The certificate's stored bundle uses a random password the
    /// operator never sees, so the Explorer's plain .p12 download would be unopenable for these.
    /// </summary>
    public async Task<ExternalRequestExportResult> ExportPkcs12Async(int id, string password, bool includeChain, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(password))
            return ExternalRequestExportResult.Failure("A password for the .p12 is required.");

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var row = await db.ExternalCertificateRequests.FindAsync([id], ct);
        if (row == null) return ExternalRequestExportResult.Failure("Request not found.");
        if (row.Status != ExternalRequestStatus.Fulfilled || row.FulfilledCertificateId is not int certId)
            return ExternalRequestExportResult.Failure("This request has not been fulfilled yet — there is no certificate to bundle.");

        byte[]? pfx;
        string? pfxPassword;
        int? issuerId;
        if (row.FulfilledEntityType == "CaCertificate")
        {
            var ca = await db.CaCertificates.FindAsync([certId], ct);
            if (ca == null) return ExternalRequestExportResult.Failure("The fulfilled certificate no longer exists.");
            (pfx, pfxPassword, issuerId) = (ca.EncryptedPfxBytes, ca.PfxPassword, ca.ParentId);
        }
        else
        {
            var issued = await db.IssuedCertificates.FindAsync([certId], ct);
            if (issued == null) return ExternalRequestExportResult.Failure("The fulfilled certificate no longer exists.");
            (pfx, pfxPassword, issuerId) = (issued.EncryptedPfxBytes, issued.PfxPassword, issued.IssuingCaCertificateId);
        }

        if (pfx == null)
            return ExternalRequestExportResult.Failure("The fulfilled certificate has no stored private key.");

        var chain = new List<X509Certificate2>();
        try
        {
            using var leaf = X509CertificateLoader.LoadPkcs12(pfx, pfxPassword,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

            var collection = new X509Certificate2Collection { leaf };
            if (includeChain)
            {
                var visited = new HashSet<int>();
                var next = issuerId;
                while (next is int caId && visited.Add(caId))
                {
                    var issuer = await db.CaCertificates.FindAsync([caId], ct);
                    if (issuer == null) break;
                    var issuerCert = X509Certificate2.CreateFromPem(issuer.X509CertificatePem);
                    chain.Add(issuerCert);
                    collection.Add(issuerCert);
                    next = issuer.ParentId;
                }
            }

            var bytes = collection.Export(X509ContentType.Pkcs12, password);
            if (bytes == null || bytes.Length == 0)
                return ExternalRequestExportResult.Failure("PKCS#12 export produced no data.");

            _logger.LogWarning("PKCS#12 with private key exported for external CA request '{Name}' (ID {Id}), chain: {Chain}", row.Name, row.Id, includeChain);

            return new ExternalRequestExportResult
            {
                Success = true,
                Bytes = bytes,
                FileName = SanitizeFileName(row.Name) + (includeChain ? "-chain.p12" : ".p12"),
                ContentType = "application/x-pkcs12"
            };
        }
        catch (Exception ex)
        {
            return ExternalRequestExportResult.Failure($"Could not build the .p12: {ex.Message}");
        }
        finally
        {
            foreach (var c in chain) c.Dispose();
        }
    }

    // ------------------------------------------------------------------ fulfil

    /// <summary>
    /// Matches the CA's certificate to the request's key, bundles it (with any chain supplied),
    /// imports it into the request's trust domain and marks the request fulfilled. When the
    /// issuer is unknown to the trust domain the result reports NeedsCaSelection; call again with
    /// <paramref name="issuingCaId"/> or include the chain.
    /// </summary>
    public async Task<FulfillExternalRequestResult> FulfillAsync(
        int id,
        byte[] certificateFile,
        string certificateFileName,
        IReadOnlyList<byte[]> chainFiles,
        int? issuingCaId = null,
        CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var row = await db.ExternalCertificateRequests.FindAsync([id], ct);
        if (row == null) return FulfillExternalRequestResult.Failure("Request not found.");
        if (row.Status == ExternalRequestStatus.Fulfilled)
            return FulfillExternalRequestResult.Failure("This request has already been fulfilled.");

        var bundle = _bundleService.Assemble(
            certificateFile, certificateFileName,
            row.EncryptedPrivateKeyPem, row.KeyPassword,
            chainFiles, row.KeyPassword, row.Name);

        if (!bundle.Success || bundle.Pkcs12Bytes == null)
            return FulfillExternalRequestResult.Failure(bundle.Error ?? "Could not match the certificate to this request's key.");

        var result = new FulfillExternalRequestResult { TrustDomainId = row.TrustDomainId, Thumbprint = bundle.Thumbprint };

        try
        {
            // Chain first so the leaf can resolve its issuer
            var chainIndex = 0;
            foreach (var der in bundle.ChainDer)
            {
                chainIndex++;
                var parsedChain = _parsingService.Parse(der, $"chain-{chainIndex}.cer");
                if (parsedChain == null) continue;
                try
                {
                    var chainName = parsedChain.Certificate.GetNameInfo(X509NameType.SimpleName, false);
                    var r = await _importService.ImportParsedCertificateAsync(parsedChain, row.TrustDomainId, name: chainName, ct: ct);
                    if (r.Success && !r.AlreadyExists) result.ChainCertificatesImported++;
                }
                finally
                {
                    parsedChain.Certificate.Dispose();
                }
            }

            var parsed = _parsingService.Parse(bundle.Pkcs12Bytes, bundle.SuggestedFileName, row.KeyPassword);
            if (parsed == null)
                return FulfillExternalRequestResult.Failure("The assembled bundle could not be re-read for import.");

            SingleImportResult import;
            try
            {
                import = await _importService.ImportParsedCertificateAsync(
                    parsed, row.TrustDomainId,
                    name: row.Name,
                    password: row.KeyPassword,
                    issuingCaId: issuingCaId,
                    ct: ct);
            }
            finally
            {
                parsed.Certificate.Dispose();
            }

            if (import.NeedsCaSelection)
            {
                result.NeedsCaSelection = true;
                result.IssuerName = bundle.Issuer;
                result.Error = $"The issuing CA ('{bundle.Issuer}') is not in this trust domain. Include the CA chain or choose the issuing CA.";
                return result;
            }
            if (!import.Success)
            {
                result.Error = import.Error ?? "Import failed.";
                return result;
            }

            // Locate the stored certificate and record lineage
            var ca = await db.CaCertificates.FirstOrDefaultAsync(c => c.Thumbprint == bundle.Thumbprint, ct);
            if (ca != null)
            {
                result.CertificateId = ca.Id;
                result.EntityType = "CaCertificate";
                result.ImportedName = ca.Name;
                if (row.ModeledOnEntityType == "CaCertificate" && row.ModeledOnCertificateId is int modelCaId
                    && await db.CaCertificates.FindAsync([modelCaId], ct) is { } modelCa)
                {
                    ca.RenewalOfId = modelCa.Id;
                    ca.Version = modelCa.Version + 1;
                }
            }
            else
            {
                var issued = await db.IssuedCertificates.FirstOrDefaultAsync(c => c.Thumbprint == bundle.Thumbprint, ct);
                if (issued == null)
                    return FulfillExternalRequestResult.Failure("Import reported success but the certificate could not be found afterwards.");

                result.CertificateId = issued.Id;
                result.EntityType = "IssuedCertificate";
                result.ImportedName = issued.Name;
                if (row.ModeledOnEntityType == "IssuedCertificate" && row.ModeledOnCertificateId is int modelIssuedId
                    && await db.IssuedCertificates.FindAsync([modelIssuedId], ct) is { } modelIssued)
                {
                    issued.RenewalOfId = modelIssued.Id;
                    issued.Version = modelIssued.Version + 1;
                }
            }

            row.Status = ExternalRequestStatus.Fulfilled;
            row.FulfilledAt = DateTime.UtcNow;
            row.FulfilledCertificateId = result.CertificateId;
            row.FulfilledEntityType = result.EntityType;
            row.FulfilledThumbprint = bundle.Thumbprint;
            await db.SaveChangesAsync(ct);

            _logger.LogInformation(
                "Fulfilled external CA request '{Name}' (ID {Id}) with certificate {Thumbprint} as {EntityType} {CertId}",
                row.Name, row.Id, bundle.Thumbprint, result.EntityType, result.CertificateId);

            result.Success = true;
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Fulfilling external CA request {Id} failed", id);
            return FulfillExternalRequestResult.Failure($"Fulfilment failed: {ex.Message}");
        }
    }

    // ------------------------------------------------------------------ lifecycle

    public async Task<bool> CancelAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var row = await db.ExternalCertificateRequests.FindAsync([id], ct);
        if (row == null || row.Status != ExternalRequestStatus.Pending) return false;
        row.Status = ExternalRequestStatus.Cancelled;
        await db.SaveChangesAsync(ct);
        return true;
    }

    /// <summary>Deletes the request and its stored private key. Irreversible.</summary>
    public async Task<bool> DeleteAsync(int id, CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var row = await db.ExternalCertificateRequests.FindAsync([id], ct);
        if (row == null) return false;
        db.ExternalCertificateRequests.Remove(row);
        await db.SaveChangesAsync(ct);
        _logger.LogWarning("Deleted external CA request '{Name}' (ID {Id}) and its private key", row.Name, row.Id);
        return true;
    }

    // ------------------------------------------------------------------ helpers

    internal static AsymmetricAlgorithm LoadKey(ExternalCertificateRequest row)
    {
        if (row.KeyAlgorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportFromEncryptedPem(row.EncryptedPrivateKeyPem, row.KeyPassword);
            return ecdsa;
        }

        var rsa = RSA.Create();
        rsa.ImportFromEncryptedPem(row.EncryptedPrivateKeyPem, row.KeyPassword);
        return rsa;
    }

    private static string SanitizeFileName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string(name.Trim().Select(c => invalid.Contains(c) || c == ' ' ? '-' : c).ToArray());
        return string.IsNullOrWhiteSpace(cleaned) ? "request" : cleaned;
    }
}
