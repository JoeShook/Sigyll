#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net.Sockets;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Shouldly;
using Sigyll.Common.Services.Signing;
using Sigyll.Pkcs11;
using Xunit;

namespace Sigyll.Signing.Tests;

/// <summary>
/// Skipped unless the PKCS #11 library is the relay client and SIGYLL_TEST_PKCS11_RELAY_FAULTS names the relay
/// server's fault switches (host:port); tools/pkcs11-relay/run-token-tests.ps1 sets both.
/// </summary>
public sealed class RelayFaultFactAttribute : FactAttribute
{
    public const string FaultsVariable = "SIGYLL_TEST_PKCS11_RELAY_FAULTS";

    public RelayFaultFactAttribute()
    {
        Skip = new SoftHsmFactAttribute().Skip;
        if (Skip == null && string.IsNullOrEmpty(Environment.GetEnvironmentVariable(FaultsVariable)))
            Skip = $"Set {FaultsVariable} to the relay server's fault switches (host:port) to run the reconnect tests.";
    }
}

/// <summary>
/// The provider keeps working when its connection to a network HSM misbehaves. The relay server (tools/pkcs11-relay)
/// stands in for the HSM and causes each failure on request.
/// </summary>
[Collection(Pkcs11TokenCollection.Name)]
public class Pkcs11ReconnectTests(SoftHsmToken token) : IClassFixture<SoftHsmToken>
{
    private static readonly byte[] Data = "to be signed"u8.ToArray();

    private Pkcs11SigningProvider Provider => token.Provider();

    [RelayFaultFact]
    public async Task Signing_Continues_AfterTheConnectionIsDropped()
    {
        var key = await Provider.GenerateKeyAsync("ECDSA", 256, "nistP256");
        await SignAndVerifyAsync(key);

        Fault("drop");

        await SignAndVerifyAsync(key);
    }

    [RelayFaultFact]
    public async Task Signing_Continues_AfterTheTokenLogsTheUserOut()
    {
        var key = await Provider.GenerateKeyAsync("ECDSA", 256, "nistP256");
        await SignAndVerifyAsync(key);

        Fault("logout");

        await SignAndVerifyAsync(key);
    }

    [RelayFaultFact]
    public async Task Signing_Continues_WhenTheAnswerToASignatureIsLost()
    {
        var key = await Provider.GenerateKeyAsync("ECDSA", 256, "nistP256");

        Fault("drop-reply Sign");

        await SignAndVerifyAsync(key);
    }

    [RelayFaultFact]
    public async Task OneKeyIsMade_WhenTheAnswerToKeyGenerationIsLost()
    {
        Fault("drop-reply GenerateKeyPair");

        var key = await Provider.GenerateKeyAsync("ECDSA", 256, "nistP256");

        // Finding the key fails when two keys carry its label, so signing shows there is exactly one.
        await SignAndVerifyAsync(key);
    }

    [RelayFaultFact]
    public async Task BothHalvesOfAKeyAreDestroyed_AfterTheTokenLogsTheUserOut()
    {
        var key = await Provider.GenerateKeyAsync("ECDSA", 256, "nistP256");

        Fault("logout");
        await Provider.DestroyKeyAsync(key.KeyIdentifier);

        // Looked for with a provider of its own, which logs in afresh: a logged-out session cannot see a private key
        // whether or not it is still there.
        using var fresh = new Pkcs11SigningProvider(Options.Create(new Pkcs11Options
        {
            LibraryPath = token.LibraryPath!,
            TokenLabel = token.Label,
            UserPin = token.UserPin,
        }), NullLogger<Pkcs11SigningProvider>.Instance);
        (await Should.ThrowAsync<InvalidOperationException>(() => fresh.GetPublicKeyAsync(key)))
            .Message.ShouldContain("not found");
        (await Should.ThrowAsync<InvalidOperationException>(() => fresh.SignDataAsync(Data, HashAlgorithmName.SHA256, key)))
            .Message.ShouldContain("not found");
    }

    private async Task SignAndVerifyAsync(SigningKeyReference key)
    {
        var signature = await Provider.SignDataAsync(Data, HashAlgorithmName.SHA256, key);

        using var publicKey = (ECDsa)await Provider.GetPublicKeyAsync(key);
        publicKey.VerifyData(Data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence).ShouldBeTrue();
    }

    /// <summary>Flips one of the relay server's fault switches.</summary>
    private static void Fault(string command)
    {
        var address = Environment.GetEnvironmentVariable(RelayFaultFactAttribute.FaultsVariable)!;
        var separator = address.LastIndexOf(':');
        using var client = new TcpClient(address[..separator], int.Parse(address[(separator + 1)..]));
        using var stream = client.GetStream();
        using var writer = new StreamWriter(stream) { AutoFlush = true, NewLine = "\n" };
        using var reader = new StreamReader(stream);
        writer.WriteLine(command);
        (reader.ReadLine() ?? "").ShouldStartWith("ok");
    }
}

/// <summary>
/// Test classes that use the PKCS #11 library run one at a time: the library is initialised once per process, so a
/// class that drops its connection would otherwise take the others' sessions with it.
/// </summary>
[CollectionDefinition(Name)]
public sealed class Pkcs11TokenCollection
{
    public const string Name = "PKCS #11 token";
}
