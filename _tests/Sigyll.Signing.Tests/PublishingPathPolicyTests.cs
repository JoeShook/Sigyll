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
using Sigyll.Common.Services.Publishing;

namespace Sigyll.Signing.Tests;

public class PublishingPathPolicyTests
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "sigyll-publish-root");

    [Fact]
    public void APlainName_ResolvesInsideTheFolder()
    {
        var policy = new PublishingPathPolicy([_root], requireAllowedRoot: true);

        var path = policy.Resolve(Path.Combine(_root, "lab"), "crls", "Lab Issuing CA (2026).crl");

        path.ShouldBe(Path.Combine(_root, "lab", "crls", "Lab Issuing CA (2026).crl"));
    }

    [Theory]
    [InlineData("../escape.crl")]
    [InlineData("..")]
    [InlineData("a/b.crl")]
    [InlineData("a\\b.crl")]
    [InlineData("C:evil.crl")]
    [InlineData("")]
    [InlineData("   ")]
    public void NamesWithPathCharacters_AreRefused(string fileName)
    {
        Should.Throw<PublishingPathException>(
            () => PublishingPathPolicy.Unrestricted.Resolve(_root, "crls", fileName));
    }

    [Fact]
    public void AFolderOutsideTheAllowedRoots_IsRefused()
    {
        var policy = new PublishingPathPolicy([_root], requireAllowedRoot: true);

        Should.Throw<PublishingPathException>(() => policy.Resolve(Path.GetTempPath(), "crls", "ca.crl"));
        Should.Throw<PublishingPathException>(() => policy.Resolve(_root + "-sibling", "crls", "ca.crl"));
        Should.Throw<PublishingPathException>(() => policy.Resolve(Path.Combine(_root, ".."), "crls", "ca.crl"));
    }

    [Fact]
    public void WithoutRoots_RequiringThemRefusesEverything_AndUnrestrictedAllowsAnyFolder()
    {
        Should.Throw<PublishingPathException>(
            () => new PublishingPathPolicy([], requireAllowedRoot: true).Resolve(_root, "crls", "ca.crl"));

        PublishingPathPolicy.Unrestricted.Resolve(Path.GetTempPath(), "crls", "ca.crl")
            .ShouldBe(Path.Combine(Path.GetTempPath(), "crls", "ca.crl"));
    }
}
