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
using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using Sigyll.Common.Data;
using Sigyll.Common.Services;
using Xunit;

namespace Sigyll.Signing.Tests;

/// <summary>The directory import with P12 files whose password isn't the default one.</summary>
public sealed class CertStorePasswordImportTests : IDisposable
{
    private const string DefaultPassword = "udap-test";
    private const string LeafPassword = "a-different-one";

    private readonly IDbContextFactory<SigyllDbContext> _dbFactory = new TestDbContextFactory();
    private readonly string _certstores = Directory.CreateTempSubdirectory("sigyll-certstores-").FullName;
    private readonly string _leafFile;

    public CertStorePasswordImportTests()
    {
        var trustDomainDir = Directory.CreateDirectory(Path.Combine(_certstores, "Password Test")).FullName;
        var issuedDir = Directory.CreateDirectory(Path.Combine(trustDomainDir, "issued")).FullName;

        using var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=Password Test Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
        using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        File.WriteAllBytes(Path.Combine(trustDomainDir, "root.pfx"), root.Export(X509ContentType.Pkcs12, DefaultPassword));

        using var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest("CN=Password Test Leaf", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false));
        using var leafPublic = leafRequest.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddMonths(6), [5, 6, 7, 8]);
        using var leaf = leafPublic.CopyWithPrivateKey(leafKey);
        _leafFile = Path.Combine(issuedDir, "leaf.p12");
        File.WriteAllBytes(_leafFile, leaf.Export(X509ContentType.Pkcs12, LeafPassword));
    }

    private CertificateImportService CreateService() =>
        new(_dbFactory, TestOperators.Full, NullLogger<CertificateImportService>.Instance);

    [Fact]
    public async Task Scan_ListsTheFileTheDefaultPasswordDoesNotOpen()
    {
        var preview = (await CreateService().ScanCertStoreAsync(_certstores, DefaultPassword)).Single();

        preview.RootCaCount.ShouldBe(1);
        preview.IssuedCertCount.ShouldBe(1);
        preview.Errors.ShouldBeEmpty();
        preview.FilesNeedingPassword.ShouldBe([Path.GetFullPath(_leafFile)]);
        preview.IsValid.ShouldBeFalse();
    }

    [Fact]
    public async Task Scan_WithThatFilesPassword_IsReady()
    {
        var passwords = new Dictionary<string, string> { [Path.GetFullPath(_leafFile)] = LeafPassword };

        var preview = (await CreateService().ScanCertStoreAsync(_certstores, DefaultPassword, passwords)).Single();

        preview.FilesNeedingPassword.ShouldBeEmpty();
        preview.IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task Import_OpensAndStoresEachFileWithItsOwnPassword()
    {
        var passwords = new Dictionary<string, string> { [Path.GetFullPath(_leafFile)] = LeafPassword };

        var (imported, errors) = await CreateService().ImportTrustDomainAsync(
            Path.Combine(_certstores, "Password Test"), DefaultPassword, passwords);

        errors.ShouldBeEmpty();
        imported.ShouldBe(2);
        await using var db = _dbFactory.CreateDbContext();
        (await db.CaCertificates.SingleAsync()).PfxPassword.ShouldBe(DefaultPassword);
        var issued = await db.IssuedCertificates.SingleAsync();
        issued.Name.ShouldBe("leaf");
        issued.PfxPassword.ShouldBe(LeafPassword);
    }

    [Fact]
    public void Pkcs12Opens_TellsARightPasswordFromAWrongOne()
    {
        CertificateImportService.Pkcs12Opens(_leafFile, LeafPassword).ShouldBeTrue();
        CertificateImportService.Pkcs12Opens(_leafFile, DefaultPassword).ShouldBeFalse();
    }

    public void Dispose() => Directory.Delete(_certstores, recursive: true);
}
