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
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Security;
using Sigyll.Common.ViewModels;

namespace Sigyll.Common.Services;

public class CertificateProfileService
{
    private readonly IDbContextFactory<SigyllDbContext> _dbFactory;
    private readonly IOperatorContext _operator;
    private readonly ILogger<CertificateProfileService> _logger;

    public CertificateProfileService(
        IDbContextFactory<SigyllDbContext> dbFactory,
        IOperatorContext operatorContext,
        ILogger<CertificateProfileService> logger)
    {
        _dbFactory = dbFactory;
        _operator = operatorContext;
        _logger = logger;
    }

    public async Task<List<CertificateProfile>> GetAllAsync(CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.View);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.CertificateProfiles
            .OrderByDescending(t => t.IsPreset)
            .ThenBy(t => t.CertificateType)
            .ThenBy(t => t.Name)
            .ToListAsync(ct);
    }

    public async Task<CertificateProfile> SaveAsync(CertificateProfile entity, CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.Administer);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);

        if (entity.Id > 0)
        {
            var existing = await db.CertificateProfiles.FindAsync([entity.Id], ct);
            if (existing != null)
            {
                db.Entry(existing).CurrentValues.SetValues(entity);
                await db.SaveChangesAsync(ct);
                return existing;
            }
        }

        db.CertificateProfiles.Add(entity);
        await db.SaveChangesAsync(ct);
        return entity;
    }

    public async Task UpdateSanListsAsync(int profileId, HashSet<int> sanListIds, CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.Administer);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var profile = await db.CertificateProfiles
            .Include(t => t.SanLists)
            .FirstOrDefaultAsync(t => t.Id == profileId, ct);
        if (profile == null) return;

        profile.SanLists.Clear();
        if (sanListIds.Count > 0)
        {
            var sanLists = await db.SanLists
                .Where(s => sanListIds.Contains(s.Id))
                .ToListAsync(ct);
            foreach (var sl in sanLists)
                profile.SanLists.Add(sl);
        }

        await db.SaveChangesAsync(ct);
    }

    public async Task<List<CertificateProfile>> GetAllWithSanListsAsync(CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.View);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        return await db.CertificateProfiles
            .Include(t => t.SanLists)
            .OrderByDescending(t => t.IsPreset)
            .ThenBy(t => t.CertificateType)
            .ThenBy(t => t.Name)
            .ToListAsync(ct);
    }

    public async Task DeleteAsync(int id, CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.Administer);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var entity = await db.CertificateProfiles.FindAsync([id], ct);
        if (entity != null && !entity.IsPreset)
        {
            db.CertificateProfiles.Remove(entity);
            await db.SaveChangesAsync(ct);
        }
    }

    public async Task<List<ImpactItem>> GetDeletionImpactAsync(int profileId, CancellationToken ct = default)
    {
        await _operator.DemandAsync(Permission.View);

        await using var db = await _dbFactory.CreateDbContextAsync(ct);
        var impacts = new List<ImpactItem>();

        var issuedCount = await db.IssuedCertificates.CountAsync(i => i.ProfileId == profileId, ct);
        if (issuedCount > 0)
            impacts.Add(new ImpactItem(issuedCount, "issued certificate(s) reference this profile", ImpactSeverity.Info));

        return impacts;
    }
}
