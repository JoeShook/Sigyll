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
using Sigyll.Contracts;
using Sigyll.Portal.Data.Entities;
using Sigyll.Portal.Services;
using Xunit;

namespace Sigyll.Signing.Tests;

public class IssuancePolicyServiceTests
{
    private readonly IssuancePolicyService _policy = new();

    private static List<ApiSanEntry> Dns(params string[] names) =>
        names.Select(n => new ApiSanEntry { Type = "Dns", Value = n }).ToList();

    [Fact]
    public void ServerCert_WithDnsSans_AutoIssues()
    {
        var template = new CatalogTemplate
        {
            Name = "SSL Server",
            CertificateType = "EndEntityServer",
            AllowAutoIssue = true,
            RequiresRaApproval = false,
        };

        var decision = _policy.Evaluate(template, Dns("api.example.com"), requesterAuthorizedForTrustDomain: false);

        decision.Kind.ShouldBe(PolicyDecisionKind.AutoIssue);
        decision.ValidationMethod.ShouldBe("http-01");
    }

    [Fact]
    public void TemplateFlaggedForRa_AlwaysRequiresApproval()
    {
        var template = new CatalogTemplate
        {
            Name = "UDAP Client",
            CertificateType = "EndEntityClient",
            AllowAutoIssue = false,
            RequiresRaApproval = true,
        };

        var decision = _policy.Evaluate(template, Dns("client.example.com"), requesterAuthorizedForTrustDomain: true);

        decision.Kind.ShouldBe(PolicyDecisionKind.RequiresRaApproval);
    }

    [Fact]
    public void ServerCert_WithNonDnsSan_FallsBackToRaApproval()
    {
        var template = new CatalogTemplate
        {
            Name = "SSL Server",
            CertificateType = "EndEntityServer",
            AllowAutoIssue = true,
        };
        var sans = new List<ApiSanEntry> { new() { Type = "Uri", Value = "https://example.com/fhir" } };

        var decision = _policy.Evaluate(template, sans, requesterAuthorizedForTrustDomain: false);

        decision.Kind.ShouldBe(PolicyDecisionKind.RequiresRaApproval);
    }

    [Fact]
    public void UnknownTemplate_IsDenied()
    {
        var decision = _policy.Evaluate(template: null, Dns("x.example.com"), requesterAuthorizedForTrustDomain: true);

        decision.Kind.ShouldBe(PolicyDecisionKind.Denied);
    }

    [Fact]
    public void NonAutoIssueTemplate_DefaultsToRaApproval()
    {
        var template = new CatalogTemplate
        {
            Name = "Custom",
            CertificateType = "EndEntityClient",
            AllowAutoIssue = false,
            RequiresRaApproval = false,
        };

        var decision = _policy.Evaluate(template, Dns("c.example.com"), requesterAuthorizedForTrustDomain: false);

        decision.Kind.ShouldBe(PolicyDecisionKind.RequiresRaApproval);
    }
}
