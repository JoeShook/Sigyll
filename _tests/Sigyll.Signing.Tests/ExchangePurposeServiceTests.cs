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
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Shouldly;
using Sigyll.Contracts;
using Sigyll.Portal.Data;
using Sigyll.Portal.Data.Entities;
using Sigyll.Portal.Services;
using Xunit;
using CertificateRequest = Sigyll.Portal.Data.Entities.CertificateRequest;

namespace Sigyll.Signing.Tests;

public class ExchangePurposeServiceTests
{
    private readonly DbContextOptions<PortalDbContext> _options = new DbContextOptionsBuilder<PortalDbContext>()
        .UseInMemoryDatabase(Guid.NewGuid().ToString())
        .Options;

    private readonly StubCaHandler _ca = new();

    private (ExchangePurposeService Service, PortalDbContext Db) Create()
    {
        var db = new PortalDbContext(_options);
        var client = new CaApiClient(new HttpClient(_ca) { BaseAddress = new Uri("https://ca.test") },
            Options.Create(new PortalOptions()));
        return (new ExchangePurposeService(db, client, new PortalAuditTrail(_options),
            NullLogger<ExchangePurposeService>.Instance), db);
    }

    private async Task<int> SeedOrgAsync(string name = "Example Clinic")
    {
        await using var db = new PortalDbContext(_options);
        var org = new Organization { Name = name };
        db.Organizations.Add(org);
        await db.SaveChangesAsync();
        return org.Id;
    }

    [Fact]
    public async Task Authorize_RecordsWhoAndWhen_AndIsAudited()
    {
        var orgId = await SeedOrgAsync();
        var (service, db) = Create();

        var row = await service.AuthorizeAsync(orgId, " t-trtmnt ", "ra@example.test");
        await service.AuthorizeAsync(orgId, "T-TRTMNT", "someone-else@example.test");

        row.Code.ShouldBe("T-TRTMNT");
        row.ApprovedBy.ShouldBe("ra@example.test");
        (await db.OrganizationExchangePurposes.CountAsync()).ShouldBe(1);
        (await service.AuthorizedCodesAsync(orgId)).ShouldBe(["T-TRTMNT"]);
        (await db.AuditEvents.SingleAsync()).Action.ShouldBe(PortalAuditActions.ExchangePurposeAuthorized);
    }

    [Fact]
    public async Task Authorize_RefusesSomethingThatIsNotACode()
    {
        var orgId = await SeedOrgAsync();
        var (service, _) = Create();

        await Should.ThrowAsync<ArgumentException>(() => service.AuthorizeAsync(orgId, "treatment", "ra"));
    }

    [Fact]
    public async Task Withdraw_RemovesTheAuthorization_AndIsAudited()
    {
        var orgId = await SeedOrgAsync();
        var (service, db) = Create();
        await service.AuthorizeAsync(orgId, "T-TRTMNT", "ra");

        (await service.WithdrawAsync(orgId, "T-TRTMNT", "ra2")).ShouldBeTrue();
        (await service.WithdrawAsync(orgId, "T-TRTMNT", "ra2")).ShouldBeFalse();

        (await service.AuthorizedCodesAsync(orgId)).ShouldBeEmpty();
        (await db.AuditEvents.CountAsync(e => e.Action == PortalAuditActions.ExchangePurposeWithdrawn)).ShouldBe(1);
    }

    [Fact]
    public void Unauthorized_ListsOnlyExchangePurposesOutsideTheAuthorizedSet()
    {
        var sans = new List<ApiSanEntry>
        {
            new() { Type = "Uri", Value = "urn:oid:1.2.3#T-TRTMNT" },
            new() { Type = "Uri", Value = "urn:oid:1.2.3#T-PYMNT" },
            new() { Type = "Uri", Value = "https://fhir.example.org/r4" },
        };

        ExchangePurposeService.Unauthorized(sans, new HashSet<string> { "T-TRTMNT" }).ShouldBe(["T-PYMNT"]);
    }

    [Fact]
    public async Task RevokeByExchangePurpose_SendsMatchingSerials_MarksRequestsRevoked_AndAudits()
    {
        var orgId = await SeedOrgAsync();
        var otherOrgId = await SeedOrgAsync("Other");
        var treatment = await SeedIssuedAsync(orgId, "urn:oid:1.2.3#T-TRTMNT");
        var payment = await SeedIssuedAsync(orgId, "urn:oid:1.2.3#T-PYMNT");
        var otherOrg = await SeedIssuedAsync(otherOrgId, "urn:oid:1.2.3#T-TRTMNT");
        _ca.Respond = req => new RevocationApiResult { Success = true, Revoked = [.. req.SerialNumbers] };

        var (service, db) = Create();
        var outcome = await service.RevokeByExchangePurposeAsync(orgId, "T-TRTMNT", "ra@example.test");

        outcome.Success.ShouldBeTrue();
        _ca.Received!.SerialNumbers.ShouldBe([treatment.Serial]);
        _ca.Received.ExchangePurpose.ShouldBe("T-TRTMNT");
        _ca.Received.RequestedBy.ShouldBe("ra@example.test");
        _ca.Received.SubscriberRef.ShouldContain("Example Clinic");

        await using var check = new PortalDbContext(_options);
        (await check.CertificateRequests.FindAsync(treatment.Id))!.Status.ShouldBe(RequestStatus.Revoked);
        (await check.CertificateRequests.FindAsync(payment.Id))!.Status.ShouldBe(RequestStatus.Issued);
        (await check.CertificateRequests.FindAsync(otherOrg.Id))!.Status.ShouldBe(RequestStatus.Issued);
        (await check.RequestEvents.SingleAsync(e => e.RequestId == treatment.Id && e.EventType == "Revoked"))
            .Detail!.ShouldContain("privilegeWithdrawn");
        var audit = await check.AuditEvents.SingleAsync(e => e.Action == PortalAuditActions.CertificatesRevokedByExchangePurpose);
        audit.Succeeded.ShouldBeTrue();
        audit.Detail!.ShouldContain(treatment.Serial);
    }

    [Fact]
    public async Task RevokeByExchangePurpose_RecordsAFailedCaCall()
    {
        var orgId = await SeedOrgAsync();
        var issued = await SeedIssuedAsync(orgId, "urn:oid:1.2.3#T-TRTMNT");
        _ca.Respond = _ => RevocationApiResult.Failure("boom");

        var (service, _) = Create();
        var outcome = await service.RevokeByExchangePurposeAsync(orgId, "T-TRTMNT", "ra");

        outcome.Success.ShouldBeFalse();
        await using var check = new PortalDbContext(_options);
        (await check.CertificateRequests.FindAsync(issued.Id))!.Status.ShouldBe(RequestStatus.Issued);
        (await check.AuditEvents.SingleAsync()).Succeeded.ShouldBeFalse();
    }

    private async Task<(int Id, string Serial)> SeedIssuedAsync(int orgId, string sanUri)
    {
        using var rsa = RSA.Create(2048);
        var req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=client", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri(sanUri));
        req.CertificateExtensions.Add(san.Build());
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        await using var db = new PortalDbContext(_options);
        var request = new CertificateRequest
        {
            RequesterId = "user",
            OrganizationId = orgId,
            TrustDomainName = "TEFCA",
            ProfileName = "Client",
            SubjectDn = "CN=client",
            RequestedSansJson = JsonSerializer.Serialize(new[] { new ApiSanEntry { Type = "Uri", Value = sanUri } }),
            Status = RequestStatus.Issued,
            SerialNumber = cert.SerialNumber,
            CertificatePem = cert.ExportCertificatePem(),
        };
        db.CertificateRequests.Add(request);
        await db.SaveChangesAsync();
        return (request.Id, cert.SerialNumber);
    }

    private sealed class StubCaHandler : HttpMessageHandler
    {
        public Func<RevocationApiRequest, RevocationApiResult> Respond { get; set; } =
            _ => new RevocationApiResult { Success = true };

        public RevocationApiRequest? Received { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Received = await request.Content!.ReadFromJsonAsync<RevocationApiRequest>(ct);
            var result = Respond(Received!);
            return new HttpResponseMessage(result.Success ? HttpStatusCode.OK : HttpStatusCode.BadRequest)
            {
                Content = JsonContent.Create(result),
            };
        }
    }
}
