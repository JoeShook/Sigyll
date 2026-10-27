#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Shouldly;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services;

namespace Sigyll.Signing.Tests;

public class ChainValidationServiceTests
{
    private readonly TestDbContextFactory _dbFactory = new();
    private readonly CountingHandler _http = new();
    private readonly ChainValidationService _service;

    public ChainValidationServiceTests()
    {
        var httpFactory = Substitute.For<IHttpClientFactory>();
        httpFactory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(_http, disposeHandler: false));
        _service = new ChainValidationService(_dbFactory, TestOperators.Full, httpFactory,
            NullLogger<ChainValidationService>.Instance);
    }

    [Fact]
    public async Task ValidateTrustDomain_DownloadsEachCrlUrlOnce_AndReusesItOnTheNextLoad()
    {
        // Unique per run: downloads are shared across validations.
        var crlUrl = $"http://crl.example.test/{Guid.NewGuid():N}.crl";
        var trustDomainId = await SeedRootWithLeavesAsync(crlUrl, leaves: 5);

        var results = await _service.ValidateTrustDomainAsync(trustDomainId);
        await _service.ValidateTrustDomainAsync(trustDomainId);

        results.Count.ShouldBe(6);
        _http.Requests.Count(r => r.StartsWith(crlUrl)).ShouldBe(1);
    }

    private async Task<int> SeedRootWithLeavesAsync(string crlUrl, int leaves)
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest("CN=Test Root", rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
        using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        await using var db = _dbFactory.CreateDbContext();
        var trustDomain = new TrustDomain { Name = "Lab", Enabled = true };
        db.TrustDomains.Add(trustDomain);
        await db.SaveChangesAsync();

        var ca = new CaCertificate
        {
            TrustDomainId = trustDomain.Id,
            Name = "Test Root",
            Subject = root.Subject,
            X509CertificatePem = root.ExportCertificatePem(),
            Thumbprint = root.Thumbprint,
            SerialNumber = root.SerialNumber,
            NotBefore = root.NotBefore,
            NotAfter = root.NotAfter,
        };
        db.CaCertificates.Add(ca);
        await db.SaveChangesAsync();

        for (var i = 0; i < leaves; i++)
        {
            using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var leafRequest = new CertificateRequest($"CN=leaf {i}", leafKey, HashAlgorithmName.SHA256);
            leafRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false));
            leafRequest.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([crlUrl]));
            using var leaf = leafRequest.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddMonths(6),
                RandomNumberGenerator.GetBytes(8));
            db.IssuedCertificates.Add(new IssuedCertificate
            {
                IssuingCaCertificateId = ca.Id,
                Name = $"leaf {i}",
                Subject = leaf.Subject,
                X509CertificatePem = leaf.ExportCertificatePem(),
                Thumbprint = leaf.Thumbprint,
                SerialNumber = leaf.SerialNumber,
                NotBefore = leaf.NotBefore,
                NotAfter = leaf.NotAfter,
            });
        }
        await db.SaveChangesAsync();
        return trustDomain.Id;
    }

    /// <summary>Answers every request with 404 and records its URL.</summary>
    private sealed class CountingHandler : HttpMessageHandler
    {
        private readonly List<string> _requests = new();

        public IReadOnlyList<string> Requests
        {
            get
            {
                lock (_requests)
                    return _requests.ToList();
            }
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            lock (_requests)
                _requests.Add(request.RequestUri!.ToString());
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }
}
