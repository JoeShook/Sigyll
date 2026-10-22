#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Shouldly;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Sigyll.Common.Data;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services;

namespace Sigyll.Signing.Tests;

public class CertificateProfileServiceTests
{
    private readonly IDbContextFactory<SigyllDbContext> _dbFactory = new TestDbContextFactory();

    private CertificateProfileService CreateService() =>
        new(_dbFactory, TestOperators.Full, NullLogger<CertificateProfileService>.Instance);

    [Fact]
    public async Task GetAll_EmptyDb_ReturnsEmpty()
    {
        var service = CreateService();

        var result = await service.GetAllAsync();

        result.ShouldBeEmpty();
    }

    [Fact]
    public async Task SaveAsync_NewProfile_CreatesAndReturnsWithId()
    {
        var service = CreateService();
        var profile = new CertificateProfile
        {
            Name = "Test Profile",
            CertificateType = CertificateType.EndEntityClient,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            ValidityDays = 365
        };

        var saved = await service.SaveAsync(profile);

        saved.Id.ShouldBeGreaterThan(0);
        saved.Name.ShouldBe("Test Profile");
    }

    [Fact]
    public async Task SaveAsync_ExistingProfile_Updates()
    {
        var service = CreateService();
        var profile = new CertificateProfile
        {
            Name = "Original",
            CertificateType = CertificateType.EndEntityClient,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            ValidityDays = 365
        };
        var saved = await service.SaveAsync(profile);

        var updated = new CertificateProfile
        {
            Id = saved.Id,
            Name = "Updated",
            CertificateType = CertificateType.EndEntityServer,
            KeyAlgorithm = "RSA",
            KeySize = 4096,
            ValidityDays = 730
        };
        await service.SaveAsync(updated);

        var all = await service.GetAllAsync();
        all.ShouldHaveSingleItem();
        all[0].Name.ShouldBe("Updated");
        all[0].KeySize.ShouldBe(4096);
    }

    [Fact]
    public async Task DeleteAsync_ExistingProfile_Removes()
    {
        var service = CreateService();
        var saved = await service.SaveAsync(new CertificateProfile
        {
            Name = "To Delete",
            CertificateType = CertificateType.RootCa,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            ValidityDays = 365
        });

        await service.DeleteAsync(saved.Id);

        var all = await service.GetAllAsync();
        all.ShouldBeEmpty();
    }

    [Fact]
    public async Task DeleteAsync_PresetProfile_DoesNotDelete()
    {
        await using var db = _dbFactory.CreateDbContext();
        db.CertificateProfiles.Add(new CertificateProfile
        {
            Name = "Preset",
            CertificateType = CertificateType.RootCa,
            KeyAlgorithm = "RSA",
            KeySize = 4096,
            ValidityDays = 3650,
            IsPreset = true
        });
        await db.SaveChangesAsync();

        var service = CreateService();
        var all = await service.GetAllAsync();
        all.ShouldHaveSingleItem();

        await service.DeleteAsync(all[0].Id);

        var afterDelete = await service.GetAllAsync();
        afterDelete.ShouldHaveSingleItem();
    }

    [Fact]
    public async Task GetAll_OrdersByPresetThenTypeThenName()
    {
        var service = CreateService();
        await service.SaveAsync(new CertificateProfile
        {
            Name = "Zebra",
            CertificateType = CertificateType.EndEntityClient,
            KeyAlgorithm = "RSA", KeySize = 2048, ValidityDays = 365
        });
        await service.SaveAsync(new CertificateProfile
        {
            Name = "Alpha",
            CertificateType = CertificateType.EndEntityClient,
            KeyAlgorithm = "RSA", KeySize = 2048, ValidityDays = 365
        });

        await using var db = _dbFactory.CreateDbContext();
        db.CertificateProfiles.Add(new CertificateProfile
        {
            Name = "Preset Root",
            CertificateType = CertificateType.RootCa,
            KeyAlgorithm = "RSA", KeySize = 4096, ValidityDays = 3650,
            IsPreset = true
        });
        await db.SaveChangesAsync();

        var all = await service.GetAllAsync();
        all.Count.ShouldBe(3);
        all[0].IsPreset.ShouldBeTrue();
        all[1].Name.ShouldBe("Alpha");
        all[2].Name.ShouldBe("Zebra");
    }
}
