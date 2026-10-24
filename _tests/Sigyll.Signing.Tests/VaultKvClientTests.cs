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
using System.Text;
using System.Text.Json.Nodes;
using NSubstitute;
using Shouldly;
using Sigyll.Common.Services.Export;
using Sigyll.Vault;

namespace Sigyll.Signing.Tests;

public class VaultKvClientTests
{
    private static readonly Uri Address = new("https://vault.example.org:8200");

    [Fact]
    public async Task Merge_KeepsTheSecretsOtherFields_AndWritesWithCheckAndSet()
    {
        var vault = new FakeVault();
        vault.Respond(HttpMethod.Get, "/v1/secret/data/team-a/lab/root",
            HttpStatusCode.OK, """{"data":{"data":{"Root.cer":"PEM","note":"kept"},"metadata":{"version":4}}}""");
        vault.Respond(HttpMethod.Post, "/v1/secret/data/team-a/lab/root",
            HttpStatusCode.OK, """{"data":{"version":5}}""");

        var version = await Client(vault).MergeAsync(Address, "hvs.t", "secret", "team-a/lab/root",
            new Dictionary<string, string> { ["Root.cer"] = "NEW", ["Root.crl"] = "CRL" });

        version.ShouldBe(5);
        var write = vault.Bodies.Single();
        write["options"]!["cas"]!.GetValue<int>().ShouldBe(4);
        write["data"]!["Root.cer"]!.GetValue<string>().ShouldBe("NEW");
        write["data"]!["Root.crl"]!.GetValue<string>().ShouldBe("CRL");
        write["data"]!["note"]!.GetValue<string>().ShouldBe("kept");
        vault.Tokens.ShouldAllBe(t => t == "hvs.t");
    }

    [Fact]
    public async Task Merge_CreatesAMissingSecret_WithCheckAndSetZero()
    {
        var vault = new FakeVault();
        vault.Respond(HttpMethod.Get, "/v1/secret/data/a/b", HttpStatusCode.NotFound, """{"errors":[]}""");
        vault.Respond(HttpMethod.Post, "/v1/secret/data/a/b", HttpStatusCode.OK, """{"data":{"version":1}}""");

        (await Client(vault).MergeAsync(Address, "t", "secret", "a/b", new Dictionary<string, string> { ["x"] = "1" }))
            .ShouldBe(1);
        vault.Bodies.Single()["options"]!["cas"]!.GetValue<int>().ShouldBe(0);
    }

    [Fact]
    public async Task Merge_RetriesWhenAnotherWriterGotThereFirst()
    {
        var vault = new FakeVault();
        vault.Respond(HttpMethod.Get, "/v1/secret/data/a/b", HttpStatusCode.OK, """{"data":{"data":{},"metadata":{"version":1}}}""");
        vault.Respond(HttpMethod.Post, "/v1/secret/data/a/b", HttpStatusCode.BadRequest,
            """{"errors":["check-and-set parameter did not match the current version"]}""");
        vault.Respond(HttpMethod.Get, "/v1/secret/data/a/b", HttpStatusCode.OK, """{"data":{"data":{"y":"2"},"metadata":{"version":2}}}""");
        vault.Respond(HttpMethod.Post, "/v1/secret/data/a/b", HttpStatusCode.OK, """{"data":{"version":3}}""");

        (await Client(vault).MergeAsync(Address, "t", "secret", "a/b", new Dictionary<string, string> { ["x"] = "1" }))
            .ShouldBe(3);
        var retry = vault.Bodies[1];
        retry["options"]!["cas"]!.GetValue<int>().ShouldBe(2);
        retry["data"]!["y"]!.GetValue<string>().ShouldBe("2");
    }

    [Fact]
    public async Task Merge_RemovesTheFieldsAskedFor_AndReadFieldNamesListsThem()
    {
        var vault = new FakeVault();
        const string current = """{"data":{"data":{"old.cer":"A","old.p12":"B","password":"p","note":"kept"},"metadata":{"version":2}}}""";
        vault.Respond(HttpMethod.Get, "/v1/secret/data/a/b", HttpStatusCode.OK, current);
        vault.Respond(HttpMethod.Get, "/v1/secret/data/a/b", HttpStatusCode.OK, current);
        vault.Respond(HttpMethod.Post, "/v1/secret/data/a/b", HttpStatusCode.OK, """{"data":{"version":3}}""");
        var client = Client(vault);

        (await client.ReadFieldNamesAsync(Address, "t", "secret", "a/b"))
            .ShouldBe(["old.cer", "old.p12", "password", "note"], ignoreOrder: true);
        await client.MergeAsync(Address, "t", "secret", "a/b",
            new Dictionary<string, string> { ["new.cer"] = "C" }, remove: ["old.cer", "old.p12", "password"]);

        var data = vault.Bodies.Single()["data"]!.AsObject();
        data.Select(f => f.Key).ShouldBe(["note", "new.cer"], ignoreOrder: true);
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.Unauthorized)]
    public async Task RefusedToken_IsReportedAsSuch(HttpStatusCode status)
    {
        var vault = new FakeVault();
        vault.Respond(HttpMethod.Get, "/v1/secret/data/a/b", status, """{"errors":["permission denied"]}""");

        var ex = await Should.ThrowAsync<VaultTokenRefusedException>(() =>
            Client(vault).MergeAsync(Address, "t", "secret", "a/b", new Dictionary<string, string> { ["x"] = "1" }));
        ex.StatusCode.ShouldBe((int)status);
    }

    [Fact]
    public async Task List_ReturnsTheKeys_AndKeepsAnAddressPath()
    {
        var vault = new FakeVault();
        vault.Respond(new HttpMethod("LIST"), "/vault/v1/secret/metadata/", HttpStatusCode.OK, """{"data":{"keys":["team-a/","x"]}}""");

        (await Client(vault).ListAsync(new Uri("https://proxy.example.org/vault"), "t", "secret", ""))
            .ShouldBe(["team-a/", "x"]);
    }

    private static VaultKvClient Client(FakeVault vault)
    {
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(VaultKvClient.HttpClientName).Returns(_ => new HttpClient(vault));
        return new VaultKvClient(factory);
    }

    /// <summary>Answers each request with the next response queued for its method and path.</summary>
    private sealed class FakeVault : HttpMessageHandler
    {
        private readonly Dictionary<string, Queue<(HttpStatusCode Status, string Body)>> _responses = new();

        public List<JsonNode> Bodies { get; } = new();
        public List<string> Tokens { get; } = new();

        public void Respond(HttpMethod method, string path, HttpStatusCode status, string body)
        {
            var key = $"{method} {path}";
            if (!_responses.TryGetValue(key, out var queue))
                _responses[key] = queue = new();
            queue.Enqueue((status, body));
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Tokens.Add(request.Headers.GetValues("X-Vault-Token").Single());
            if (request.Content != null)
                Bodies.Add(JsonNode.Parse(await request.Content.ReadAsStringAsync(ct))!);

            var (status, body) = _responses[$"{request.Method} {request.RequestUri!.AbsolutePath}"].Dequeue();
            return new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        }
    }
}
