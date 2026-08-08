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
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;

namespace Sigyll.Common.Services;

public class CertificateExportResult
{
    public bool Success { get; set; }
    public string? Pem { get; set; }
    public string? Error { get; set; }

    public static CertificateExportResult Ok(string pem) => new() { Success = true, Pem = pem };
    public static CertificateExportResult Failure(string error) => new() { Success = false, Error = error };
}

public class PfxExportResult
{
    public bool Success { get; set; }
    public byte[]? PfxBytes { get; set; }
    public string? FileName { get; set; }
    public string? Error { get; set; }

    public static PfxExportResult Ok(byte[] pfxBytes, string fileName) =>
        new() { Success = true, PfxBytes = pfxBytes, FileName = fileName };
    public static PfxExportResult Failure(string error) => new() { Success = false, Error = error };
}

public class CertificateExportService
{
    private readonly IDbContextFactory<SigyllDbContext> _dbFactory;
    private readonly ILogger<CertificateExportService> _logger;

    public CertificateExportService(
        IDbContextFactory<SigyllDbContext> dbFactory,
        ILogger<CertificateExportService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    public async Task<CertificateExportResult> ExportPrivateKeyPemAsync(
        int certificateId,
        string entityType,
        CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        byte[]? pfxBytes;
        string? pfxPassword;
        CertSecurityLevel securityLevel;

        if (entityType == "CaCertificate")
        {
            var ca = await db.CaCertificates.FindAsync([certificateId], ct);
            if (ca == null)
                return CertificateExportResult.Failure("Certificate not found.");
            pfxBytes = ca.EncryptedPfxBytes;
            pfxPassword = ca.PfxPassword;
            securityLevel = ca.CertSecurityLevel;
        }
        else
        {
            var issued = await db.IssuedCertificates.FindAsync([certificateId], ct);
            if (issued == null)
                return CertificateExportResult.Failure("Certificate not found.");
            pfxBytes = issued.EncryptedPfxBytes;
            pfxPassword = issued.PfxPassword;
            securityLevel = issued.CertSecurityLevel;
        }

        if (securityLevel != CertSecurityLevel.Software)
            return CertificateExportResult.Failure(
                "Private key export is not permitted for this security level. " +
                "Keys stored in HSM or cloud KMS cannot be extracted.");

        if (pfxBytes == null)
            return CertificateExportResult.Failure("No private key available for this certificate.");

        try
        {
            using var cert = X509CertificateLoader.LoadPkcs12(pfxBytes, pfxPassword,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

            using var rsa = cert.GetRSAPrivateKey();
            if (rsa != null)
                return CertificateExportResult.Ok(rsa.ExportPkcs8PrivateKeyPem());

            using var ecdsa = cert.GetECDsaPrivateKey();
            if (ecdsa != null)
                return CertificateExportResult.Ok(ecdsa.ExportPkcs8PrivateKeyPem());

            return CertificateExportResult.Failure("Unsupported key algorithm.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to export private key for {EntityType} ID {Id}", entityType, certificateId);
            return CertificateExportResult.Failure($"Failed to export private key: {ex.Message}");
        }
    }

    /// <summary>
    /// Exports the stored PKCS#12 for a certificate, optionally rebuilding it to include the
    /// issuing CA chain. Only the leaf certificate's private key is ever exported — chain
    /// certificates are added as public certs only. The result is protected with the same
    /// password as the stored PFX.
    /// </summary>
    public async Task<PfxExportResult> ExportPfxAsync(
        int certificateId,
        string entityType,
        bool includeChain,
        CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        byte[]? pfxBytes;
        string? pfxPassword;
        string name;
        int? issuerCaId;

        if (entityType == "CaCertificate")
        {
            var ca = await db.CaCertificates.FindAsync([certificateId], ct);
            if (ca == null)
                return PfxExportResult.Failure("Certificate not found.");
            pfxBytes = ca.EncryptedPfxBytes;
            pfxPassword = ca.PfxPassword;
            name = ca.Name;
            issuerCaId = ca.ParentId;
        }
        else
        {
            var issued = await db.IssuedCertificates.FindAsync([certificateId], ct);
            if (issued == null)
                return PfxExportResult.Failure("Certificate not found.");
            pfxBytes = issued.EncryptedPfxBytes;
            pfxPassword = issued.PfxPassword;
            name = issued.Name;
            issuerCaId = issued.IssuingCaCertificateId;
        }

        if (pfxBytes == null)
            return PfxExportResult.Failure("No private key available for this certificate.");

        if (!includeChain || issuerCaId == null)
            return PfxExportResult.Ok(pfxBytes, $"{name}.p12");

        var chainCerts = new List<X509Certificate2>();
        try
        {
            using var leaf = X509CertificateLoader.LoadPkcs12(pfxBytes, pfxPassword,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

            var visited = new HashSet<int>();
            var nextId = issuerCaId;
            while (nextId is int caId && visited.Add(caId))
            {
                var issuer = await db.CaCertificates.FindAsync([caId], ct);
                if (issuer == null) break;
                chainCerts.Add(X509Certificate2.CreateFromPem(issuer.X509CertificatePem));
                nextId = issuer.ParentId;
            }

            var collection = new X509Certificate2Collection { leaf };
            collection.AddRange(chainCerts.ToArray());

            var bytes = collection.Export(X509ContentType.Pkcs12, pfxPassword);
            if (bytes == null)
                return PfxExportResult.Failure("PKCS#12 export produced no data.");

            return PfxExportResult.Ok(bytes, $"{name}-chain.p12");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to export PKCS#12 with chain for {EntityType} ID {Id}", entityType, certificateId);
            return PfxExportResult.Failure($"Failed to export PKCS#12: {ex.Message}");
        }
        finally
        {
            foreach (var c in chainCerts) c.Dispose();
        }
    }

    public async Task<CertificateExportResult> ExportCertificateDerBase64Async(
        int certificateId,
        string entityType,
        CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        string? pem;

        if (entityType == "CaCertificate")
        {
            var ca = await db.CaCertificates.FindAsync([certificateId], ct);
            if (ca == null)
                return CertificateExportResult.Failure("Certificate not found.");
            pem = ca.X509CertificatePem;
        }
        else
        {
            var issued = await db.IssuedCertificates.FindAsync([certificateId], ct);
            if (issued == null)
                return CertificateExportResult.Failure("Certificate not found.");
            pem = issued.X509CertificatePem;
        }

        try
        {
            using var cert = X509Certificate2.CreateFromPem(pem);
            var derBytes = cert.RawData;
            var base64 = Convert.ToBase64String(derBytes);
            return CertificateExportResult.Ok(base64);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to export certificate DER for {EntityType} ID {Id}", entityType, certificateId);
            return CertificateExportResult.Failure($"Failed to export certificate: {ex.Message}");
        }
    }
}
