#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text.RegularExpressions;
using Shouldly;
using Sigyll.Vault;

namespace Sigyll.Signing.Tests;

public class VaultTransitKeyNameTests
{
    [Theory]
    [InlineData("ca My Vault Transit CA", "sigyll-ca-my-vault-transit-ca-")]
    [InlineData("ca CN=Acme Root CA, O=Acme, C=US", "sigyll-ca-cn-acme-root-ca-o-acme-c-us-")]
    [InlineData("cert  fhir.example.com / TLS ", "sigyll-cert-fhir-example-com-tls-")]
    [InlineData("ca Société Générale Émetteur", "sigyll-ca-societe-generale-emetteur-")]
    public void A_key_is_named_for_what_it_holds(string label, string expectedStart)
    {
        var name = VaultTransitSigningProvider.BuildKeyName(label);

        name.ShouldStartWith(expectedStart);
        name[expectedStart.Length..].ShouldMatch("^[0-9a-f]{8}$");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" / ")]
    public void A_key_without_a_usable_label_still_gets_Sigylls_prefix(string? label) =>
        VaultTransitSigningProvider.BuildKeyName(label).ShouldMatch("^sigyll-[0-9a-f]{8}$");

    [Fact]
    public void A_name_holds_only_what_Transit_accepts_and_stays_short()
    {
        var name = VaultTransitSigningProvider.BuildKeyName("ca " + new string('x', 200) + " ünïcödé/..%");

        Regex.IsMatch(name, "^[a-z0-9-]+$").ShouldBeTrue(name);
        name.Length.ShouldBeLessThanOrEqualTo("sigyll-".Length + 48 + 1 + 8);
        name.ShouldNotContain("--");
    }

    [Fact]
    public void Two_keys_with_the_same_label_get_different_names() =>
        VaultTransitSigningProvider.BuildKeyName("ca Same").ShouldNotBe(VaultTransitSigningProvider.BuildKeyName("ca Same"));
}
