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
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Shouldly;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services;
using Sigyll.Common.Services.Jobs;
using Sigyll.Common.Services.Signing;
using Sigyll.Common.ViewModels;
using Sigyll.Pkcs11;
using Xunit;

namespace Sigyll.Signing.Tests;

/// <summary>
/// Skipped unless a real token is named. Unlike <see cref="SoftHsmFactAttribute"/>, this never initializes a token:
/// the token must already have a user PIN. <c>tools/opensc/run-hardware-tests.ps1</c> sets the variables.
/// </summary>
public sealed class HardwareHsmFactAttribute : FactAttribute
{
    public const string LibraryVariable = "SIGYLL_TEST_HSM_LIB";
    public const string PinVariable = "SIGYLL_TEST_HSM_PIN";
    public const string LabelVariable = "SIGYLL_TEST_HSM_LABEL";

    public HardwareHsmFactAttribute()
    {
        var path = Environment.GetEnvironmentVariable(LibraryVariable);
        if (string.IsNullOrEmpty(path) || !File.Exists(path)
            || string.IsNullOrEmpty(Environment.GetEnvironmentVariable(PinVariable))
            || string.IsNullOrEmpty(Environment.GetEnvironmentVariable(LabelVariable)))
        {
            Skip = $"Set {LibraryVariable}, {PinVariable} and {LabelVariable} to test a PKCS #11 token that is already initialized.";
        }
    }
}

/// <summary>
/// Skipped unless the operator has also asked for it: someone has to take the token out and put it back while the
/// test runs. <c>tools/opensc/run-hardware-tests.ps1 -Replug</c> sets the variable.
/// </summary>
public sealed class HardwareHsmReplugFactAttribute : FactAttribute
{
    public const string ReplugVariable = "SIGYLL_TEST_HSM_REPLUG";

    public HardwareHsmReplugFactAttribute()
    {
        Skip = new HardwareHsmFactAttribute().Skip;
        if (Skip == null && Environment.GetEnvironmentVariable(ReplugVariable) != "1")
            Skip = $"Set {ReplugVariable} to 1, then remove the token and put it back while the test runs.";
    }
}

/// <summary>One session on a token the operator has already initialized. Nothing here calls C_InitToken.</summary>
public sealed class HardwareHsmToken : IDisposable
{
    public Pkcs11SigningProvider? Provider { get; }

    public HardwareHsmToken()
    {
        var library = Environment.GetEnvironmentVariable(HardwareHsmFactAttribute.LibraryVariable);
        var pin = Environment.GetEnvironmentVariable(HardwareHsmFactAttribute.PinVariable);
        var label = Environment.GetEnvironmentVariable(HardwareHsmFactAttribute.LabelVariable);
        if (string.IsNullOrEmpty(library) || !File.Exists(library) || string.IsNullOrEmpty(pin) || string.IsNullOrEmpty(label))
            return;

        Provider = new Pkcs11SigningProvider(Options.Create(new Pkcs11Options
        {
            LibraryPath = library,
            TokenLabel = label,
            UserPin = pin,
            // A Nitrokey HSM is Common Criteria, not FIPS 140-3, so its keys stay recorded as software-protected.
            HardwareProtected = false,
        }), NullLogger<Pkcs11SigningProvider>.Instance);
    }

    public void Dispose() => Provider?.Dispose();
}

/// <summary>Signing on a hardware PKCS #11 token through its vendor library. OpenSC is the library for a Nitrokey HSM.</summary>
public class Pkcs11HardwareTokenTests(HardwareHsmToken token) : IClassFixture<HardwareHsmToken>
{
    private readonly TestDbContextFactory _dbFactory = new();

    [HardwareHsmFact]
    public async Task EcdsaP256_SignsOnTheToken_AndTheKeyCannotLeaveIt()
    {
        await WithKey("ECDSA", 256, "nistP256", async key =>
        {
            var data = "to be signed"u8.ToArray();
            var signature = await token.Provider!.SignDataAsync(data, HashAlgorithmName.SHA256, key);

            using var publicKey = (ECDsa)await token.Provider.GetPublicKeyAsync(key);
            publicKey.KeySize.ShouldBe(256);
            publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)
                .ShouldBeTrue();

            var flags = await token.Provider.GetPrivateKeyFlagsAsync(key.KeyIdentifier);
            flags.Local.ShouldBeTrue("generated on the token");
            flags.Sensitive.ShouldBeTrue();
            flags.Extractable.ShouldBeFalse();
            flags.NeverExtractable.ShouldBeTrue();
            token.Provider.NewKeySecurityLevel.ShouldBe(CertSecurityLevel.CloudKms);
        });
    }

    [HardwareHsmFact]
    public async Task EcdsaP384_SignsOnTheToken()
    {
        await WithKey("ECDSA", 384, "nistP384", async key =>
        {
            var data = "to be signed"u8.ToArray();
            var signature = await token.Provider!.SignDataAsync(data, HashAlgorithmName.SHA384, key);

            using var publicKey = (ECDsa)await token.Provider.GetPublicKeyAsync(key);
            publicKey.KeySize.ShouldBe(384);
            publicKey.VerifyData(data, signature, HashAlgorithmName.SHA384, DSASignatureFormat.Rfc3279DerSequence)
                .ShouldBeTrue();
        });
    }

    [HardwareHsmFact]
    public async Task Rsa2048_SignsOnTheToken()
    {
        await WithKey("RSA", 2048, null, async key =>
        {
            var data = "to be signed"u8.ToArray();
            var signature = await token.Provider!.SignDataAsync(data, HashAlgorithmName.SHA256, key);

            using var publicKey = (RSA)await token.Provider.GetPublicKeyAsync(key);
            publicKey.KeySize.ShouldBe(2048);
            publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).ShouldBeTrue();
        });
    }

    /// <summary>
    /// The operator removes the token and puts it back while this runs. Signing fails while the token is away and
    /// must work again, with the same key, once it is back: the provider signs in again by itself.
    /// </summary>
    [HardwareHsmReplugFact]
    public async Task Signing_Continues_AfterTheTokenIsRemovedAndPutBack()
    {
        await WithKey("ECDSA", 256, "nistP256", async key =>
        {
            var data = "to be signed"u8.ToArray();
            using var publicKey = (ECDsa)await token.Provider!.GetPublicKeyAsync(key);
            await token.Provider.SignDataAsync(data, HashAlgorithmName.SHA256, key);

            var removed = false;
            var giveUp = DateTime.UtcNow.AddMinutes(3);
            while (true)
            {
                byte[]? signature = null;
                try
                {
                    signature = await token.Provider.SignDataAsync(data, HashAlgorithmName.SHA256, key);
                }
                catch (Exception)
                {
                    removed = true;
                }

                if (removed && signature != null)
                {
                    publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)
                        .ShouldBeTrue();
                    return;
                }

                (DateTime.UtcNow < giveUp).ShouldBeTrue(removed
                    ? "The token was removed, but signing did not work again within three minutes of the start."
                    : "The token was never removed: signing kept working for three minutes.");
                await Task.Delay(TimeSpan.FromSeconds(1));
            }
        });
    }

    [HardwareHsmFact]
    public async Task TokenCa_IssuesACertificate_AndSignsItsCrl()
    {
        var (trustDomainId, rootProfileId, leafProfileId) = await SeedAsync();
        var issuance = new CertificateIssuanceService(_dbFactory, TestOperators.Full,
            NullLogger<CertificateIssuanceService>.Instance, token.Provider!);
        int? rootId = null;
        try
        {
            var root = await issuance.IssueCertificateAsync(new CertificateIssuanceRequest
            {
                ProfileId = rootProfileId,
                TrustDomainId = trustDomainId,
                SubjectDn = "CN=Token Root",
                CertificateName = "Token Root",
            });
            root.Success.ShouldBeTrue(root.Error);
            rootId = root.EntityId;

            var leaf = await issuance.IssueCertificateAsync(new CertificateIssuanceRequest
            {
                IssuingCaCertificateId = root.EntityId,
                ProfileId = leafProfileId,
                TrustDomainId = trustDomainId,
                SubjectDn = "CN=api.example.com",
                CertificateName = "api",
                PfxPassword = "test-password",
                SubjectAltNames = [new SanEntry(SanType.Dns, "api.example.com")],
                SigningProviderOverride = "local",
            });
            leaf.Success.ShouldBeTrue(leaf.Error);

            await using var db = _dbFactory.CreateDbContext();
            var rootEntity = (await db.CaCertificates.FindAsync(root.EntityId))!;
            rootEntity.StoreProviderHint.ShouldStartWith("pkcs11:");
            rootEntity.EncryptedPfxBytes.ShouldBeNull();
            rootEntity.CertSecurityLevel.ShouldBe(CertSecurityLevel.CloudKms);

            using var rootCert = X509Certificate2.CreateFromPem(rootEntity.X509CertificatePem);
            using var leafCert = X509Certificate2.CreateFromPem(
                (await db.IssuedCertificates.FindAsync(leaf.EntityId))!.X509CertificatePem);
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(rootCert);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.Build(leafCert).ShouldBeTrue(string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation)));

            var crls = new CrlGenerationService(_dbFactory, TestOperators.Full,
                NullLogger<CrlGenerationService>.Instance, token.Provider!);
            var crl = await crls.GenerateCrlAsync(root.EntityId!.Value);
            crl.IsSuccess.ShouldBeTrue(crl.Error);
        }
        finally
        {
            if (rootId != null)
            {
                await using var db = _dbFactory.CreateDbContext();
                var hint = (await db.CaCertificates.FindAsync(rootId))?.StoreProviderHint;
                if (hint != null && hint.StartsWith("pkcs11:", StringComparison.Ordinal))
                    await token.Provider!.DestroyKeyAsync(hint["pkcs11:".Length..]);
            }
        }
    }

    private async Task WithKey(string algorithm, int size, string? curve, Func<SigningKeyReference, Task> assert)
    {
        var key = await token.Provider!.GenerateKeyAsync(algorithm, size, curve);
        try
        {
            await assert(key);
        }
        finally
        {
            await token.Provider.DestroyKeyAsync(key.KeyIdentifier);
        }
    }

    private async Task<(int TrustDomainId, int RootProfileId, int LeafProfileId)> SeedAsync()
    {
        await using var db = _dbFactory.CreateDbContext();
        var trustDomain = new TrustDomain { Name = "Token TD", Enabled = true };
        db.TrustDomains.Add(trustDomain);
        var root = new CertificateProfile
        {
            Name = "Root",
            CertificateType = CertificateType.RootCa,
            KeyAlgorithm = "ECDSA",
            EcdsaCurve = "nistP384",
            KeySize = 384,
            ValidityDays = 3650,
            KeyUsageFlags = (int)(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign),
            IsBasicConstraintsCa = true,
            HashAlgorithm = "SHA384",
        };
        var leaf = new CertificateProfile
        {
            Name = "Server",
            CertificateType = CertificateType.EndEntityServer,
            KeyAlgorithm = "RSA",
            KeySize = 2048,
            ValidityDays = 365,
            KeyUsageFlags = (int)X509KeyUsageFlags.DigitalSignature,
            ExtendedKeyUsageOids = "1.3.6.1.5.5.7.3.1",
            HashAlgorithm = "SHA256",
        };
        db.CertificateProfiles.AddRange(root, leaf);
        await db.SaveChangesAsync();
        return (trustDomain.Id, root.Id, leaf.Id);
    }
}

public class OpenScConfigurationTests
{
    [Fact]
    public void ProfilesBesideTheLibrary_AreWrittenIntoOpenScConf()
    {
        var root = Directory.CreateTempSubdirectory("sigyll-opensc-");
        var previous = Environment.GetEnvironmentVariable("OPENSC_CONF");
        try
        {
            Directory.CreateDirectory(Path.Combine(root.FullName, "pkcs11"));
            Directory.CreateDirectory(Path.Combine(root.FullName, "profiles"));
            File.WriteAllText(Path.Combine(root.FullName, "profiles", "pkcs15.profile"), "# test");
            var library = Path.Combine(root.FullName, "pkcs11", "opensc-pkcs11.dll");
            File.WriteAllText(library, "");
            Environment.SetEnvironmentVariable("OPENSC_CONF", null);

            OpenScConfiguration.UseProfilesBesideLibrary(library);

            if (OperatingSystem.IsWindows())
            {
                var conf = Environment.GetEnvironmentVariable("OPENSC_CONF");
                conf.ShouldNotBeNullOrEmpty();
                File.ReadAllText(conf).ShouldContain(Path.Combine(root.FullName, "profiles").Replace('\\', '/'));
            }
            else
            {
                Environment.GetEnvironmentVariable("OPENSC_CONF").ShouldBeNull();
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("OPENSC_CONF", previous);
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public void AnExistingOpenScConf_IsLeftAlone()
    {
        var root = Directory.CreateTempSubdirectory("sigyll-opensc-");
        var previous = Environment.GetEnvironmentVariable("OPENSC_CONF");
        try
        {
            Directory.CreateDirectory(Path.Combine(root.FullName, "profiles"));
            File.WriteAllText(Path.Combine(root.FullName, "profiles", "pkcs15.profile"), "# test");
            Environment.SetEnvironmentVariable("OPENSC_CONF", "C:/kept/opensc.conf");

            OpenScConfiguration.UseProfilesBesideLibrary(Path.Combine(root.FullName, "pkcs11", "opensc-pkcs11.dll"));

            Environment.GetEnvironmentVariable("OPENSC_CONF").ShouldBe("C:/kept/opensc.conf");
        }
        finally
        {
            Environment.SetEnvironmentVariable("OPENSC_CONF", previous);
            root.Delete(recursive: true);
        }
    }
}
