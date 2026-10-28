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
using Sigyll.Common.Security;

namespace Sigyll.Signing.Tests;

public class RaApiKeyTests
{
    private const string StrongKey = "q3V9xR2mT7kW1pZ8cN4bJ6hF0dL5sG2a";

    [Fact]
    public void Outside_Development_ThePlaceholderAndShortKeysAreRefused()
    {
        RaApiKey.Problem(RaApiKey.DevelopmentPlaceholder, isDevelopment: false)!.ShouldContain("placeholder");
        RaApiKey.Problem("too-short", isDevelopment: false)!.ShouldContain($"{RaApiKey.MinimumLength}");
        RaApiKey.Problem(StrongKey, isDevelopment: false).ShouldBeNull();
    }

    [Fact]
    public void NoKey_TurnsTheApiOff_RatherThanRefusingToStart()
    {
        RaApiKey.Problem(null, isDevelopment: false).ShouldBeNull();
        RaApiKey.Problem("", isDevelopment: false).ShouldBeNull();
        RaApiKey.Matches("anything", null).ShouldBeFalse();
    }

    [Fact]
    public void Development_AcceptsThePlaceholder()
    {
        RaApiKey.Problem(RaApiKey.DevelopmentPlaceholder, isDevelopment: true).ShouldBeNull();
    }

    [Fact]
    public void Matches_OnlyTheExactKey()
    {
        RaApiKey.Matches(StrongKey, StrongKey).ShouldBeTrue();
        RaApiKey.Matches(StrongKey.ToUpperInvariant(), StrongKey).ShouldBeFalse();
        RaApiKey.Matches(StrongKey[..^1], StrongKey).ShouldBeFalse();
        RaApiKey.Matches(StrongKey + "x", StrongKey).ShouldBeFalse();
        RaApiKey.Matches("", StrongKey).ShouldBeFalse();
        RaApiKey.Matches(null, StrongKey).ShouldBeFalse();
    }
}
