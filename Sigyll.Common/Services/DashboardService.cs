#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sigyll.Common.Data;
using Sigyll.Common.ViewModels;

namespace Sigyll.Common.Services;

public class DashboardService
{
    private readonly IDbContextFactory<SigyllDbContext> _dbFactory;
    private readonly ILogger<DashboardService> _logger;

    public DashboardService(
        IDbContextFactory<SigyllDbContext> dbFactory,
        ILogger<DashboardService> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    public async Task<DashboardData> GetDashboardAsync(CancellationToken ct = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        var expiringSoonThreshold = now.AddDays(60);

        var data = new DashboardData
        {
            TrustDomainCount = await db.TrustDomains.CountAsync(ct),
            CaCertCount = await db.CaCertificates.CountAsync(ca => !ca.IsArchived, ct),
            IssuedCertCount = await db.IssuedCertificates.CountAsync(i => !i.IsArchived, ct),
            ProfileCount = await db.CertificateProfiles.CountAsync(ct),
            RevokedCertCount = await db.IssuedCertificates.CountAsync(i => i.IsRevoked && !i.IsArchived, ct)
        };

        // Archived certificates are out of every count, and revoked ones are out of the expired and
        // expiring counts, so the trust domain cards agree with the lists below them. A certificate
        // with auto-renew off is being left to expire on purpose: it is counted and listed as "not
        // renewing" instead of expired or expiring, and raises no warning. A CRL is
        // overdue only when it is the newest CRL its CA has published: re-signing leaves every
        // earlier CRL behind with a past NextUpdate, and counting those reported hundreds of overdue
        // CRLs for CAs whose current CRL was fine.

        data.TrustDomainSummaries = await db.TrustDomains
            .Select(c => new TrustDomainSummary
            {
                Id = c.Id,
                Name = c.Name,
                CaCount = c.CaCertificates.Count(ca => !ca.IsArchived),
                IssuedCount = c.CaCertificates
                    .SelectMany(ca => ca.IssuedCertificates)
                    .Count(i => !i.IsArchived),
                ExpiredCaCount = c.CaCertificates.Count(ca => ca.NotAfter <= now && ca.AutoRenew && !ca.IsArchived),
                ExpiredIssuedCount = c.CaCertificates
                    .SelectMany(ca => ca.IssuedCertificates)
                    .Count(i => i.NotAfter <= now && i.AutoRenew && !i.IsRevoked && !i.IsArchived),
                ExpiringCaCount = c.CaCertificates
                    .Count(ca => ca.NotAfter > now && ca.NotAfter <= expiringSoonThreshold && ca.AutoRenew && !ca.IsArchived),
                ExpiringIssuedCount = c.CaCertificates
                    .SelectMany(ca => ca.IssuedCertificates)
                    .Count(i => i.NotAfter > now && i.NotAfter <= expiringSoonThreshold && i.AutoRenew && !i.IsRevoked && !i.IsArchived),
                NotRenewingCount = c.CaCertificates
                        .Count(ca => ca.NotAfter <= expiringSoonThreshold && !ca.AutoRenew && !ca.IsArchived)
                    + c.CaCertificates
                        .SelectMany(ca => ca.IssuedCertificates)
                        .Count(i => i.NotAfter <= expiringSoonThreshold && !i.AutoRenew && !i.IsRevoked && !i.IsArchived),
                OverdueCrlCount = c.CaCertificates
                    .Where(ca => !ca.IsArchived)
                    .Count(ca => ca.Crls
                        .Where(crl => !crl.IsArchived)
                        .OrderByDescending(crl => crl.ThisUpdate)
                        .Select(crl => (DateTime?)crl.NextUpdate)
                        .FirstOrDefault() < now),
            })
            .OrderBy(c => c.Name)
            .ToListAsync(ct);

        // Every live certificate that has expired or expires within the warning window, split in
        // memory: auto-renew on is expiring or expired, auto-renew off is not renewing.
        var dueCas = await db.CaCertificates
            .Where(c => c.NotAfter <= expiringSoonThreshold && !c.IsArchived)
            .Select(c => new CertRow
            {
                Name = c.Name,
                Subject = c.Subject,
                Thumbprint = c.Thumbprint,
                NotAfter = c.NotAfter,
                TrustDomainName = c.TrustDomain.Name,
                TrustDomainId = c.TrustDomainId,
                CertType = "CA",
                DaysRemaining = (int)(c.NotAfter - now).TotalDays,
                IsExpired = c.NotAfter <= now,
                AutoRenew = c.AutoRenew
            })
            .ToListAsync(ct);

        var dueIssued = await db.IssuedCertificates
            .Where(i => i.NotAfter <= expiringSoonThreshold && !i.IsRevoked && !i.IsArchived)
            .Select(i => new CertRow
            {
                Name = i.Name,
                Subject = i.Subject,
                Thumbprint = i.Thumbprint,
                NotAfter = i.NotAfter,
                TrustDomainName = i.IssuingCaCertificate.TrustDomain.Name,
                TrustDomainId = i.IssuingCaCertificate.TrustDomainId,
                CertType = "End Entity",
                DaysRemaining = (int)(i.NotAfter - now).TotalDays,
                IsExpired = i.NotAfter <= now,
                AutoRenew = i.AutoRenew
            })
            .ToListAsync(ct);

        var due = dueCas.Concat(dueIssued).ToList();

        data.ExpiringCerts = due
            .Where(c => c.AutoRenew && !c.IsExpired)
            .OrderBy(c => c.NotAfter)
            .ToList();

        data.ExpiredCerts = due
            .Where(c => c.AutoRenew && c.IsExpired)
            .OrderByDescending(c => c.NotAfter)
            .Take(20)
            .ToList();

        data.NotRenewingCerts = due
            .Where(c => !c.AutoRenew)
            .OrderByDescending(c => c.NotAfter)
            .ToList();

        data.OverdueCrls = await db.Crls
            .Where(c => c.NextUpdate < now && !c.IsArchived && !c.CaCertificate.IsArchived)
            .Where(c => !c.CaCertificate.Crls.Any(newer => !newer.IsArchived && newer.ThisUpdate > c.ThisUpdate))
            .Select(c => new CrlRow
            {
                CrlNumber = c.CrlNumber,
                CaName = c.CaCertificate.Name,
                CaThumbprint = c.CaCertificate.Thumbprint,
                TrustDomainName = c.CaCertificate.TrustDomain.Name,
                TrustDomainId = c.CaCertificate.TrustDomainId,
                NextUpdate = c.NextUpdate,
                DaysOverdue = (int)(now - c.NextUpdate).TotalDays
            })
            .OrderByDescending(c => c.DaysOverdue)
            .ToListAsync(ct);

        return data;
    }
}
