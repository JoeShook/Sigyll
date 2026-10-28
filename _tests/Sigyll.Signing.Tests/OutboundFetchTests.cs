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
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using Sigyll.ServiceDefaults;

namespace Sigyll.Signing.Tests;

public class OutboundFetchTests
{
    [Theory]
    [InlineData("169.254.169.254", false, true)]   // cloud metadata: always refused
    [InlineData("0.0.0.0", false, true)]
    [InlineData("224.0.0.1", false, true)]
    [InlineData("fe80::1", false, true)]
    [InlineData("10.1.2.3", true, true)]
    [InlineData("172.20.0.1", true, true)]
    [InlineData("192.168.1.1", true, true)]
    [InlineData("127.0.0.1", true, true)]
    [InlineData("100.64.0.1", true, true)]
    [InlineData("::1", true, true)]
    [InlineData("fd00::1", true, true)]
    [InlineData("::ffff:10.0.0.1", true, true)]
    [InlineData("10.1.2.3", false, false)]          // private allowed when the host is allow-listed
    [InlineData("127.0.0.1", false, false)]
    [InlineData("8.8.8.8", true, false)]
    [InlineData("2606:4700:4700::1111", true, false)]
    public void Addresses_AreRefusedByCategory(string address, bool blockPrivate, bool refused) =>
        OutboundFetch.IsRefused(IPAddress.Parse(address), blockPrivate).ShouldBe(refused);

    [Fact]
    public void AllowedHosts_MatchExactNamesAndDotSuffixes()
    {
        string[] allowed = ["localhost", ".pki.example.test"];
        OutboundFetch.IsAllowedHost("LOCALHOST", allowed).ShouldBeTrue();
        OutboundFetch.IsAllowedHost("crl.pki.example.test", allowed).ShouldBeTrue();
        OutboundFetch.IsAllowedHost("pki.example.test.evil.test", allowed).ShouldBeFalse();
        OutboundFetch.IsAllowedHost("evilpki.example.test", allowed).ShouldBeFalse();
    }

    [Fact]
    public async Task Loopback_IsRefused_UnlessTheHostIsAllowed()
    {
        await using var server = await StartServerAsync();
        var port = new Uri(Address(server)).Port;

        using var blocked = Client(new OutboundFetchOptions());
        var ex = await Should.ThrowAsync<HttpRequestException>(() => blocked.GetStringAsync($"http://localhost:{port}/ok"));
        ex.InnerException.ShouldBeOfType<OutboundFetchBlockedException>();

        using var allowed = Client(new OutboundFetchOptions { AllowedHosts = ["localhost"] });
        (await allowed.GetStringAsync($"http://localhost:{port}/ok")).ShouldBe("ok");
    }

    [Fact]
    public async Task ARedirectToTheMetadataAddress_IsRefused_EvenFromAnAllowedHost()
    {
        await using var server = await StartServerAsync();
        var port = new Uri(Address(server)).Port;
        using var client = Client(new OutboundFetchOptions { AllowedHosts = ["localhost"] });

        var ex = await Should.ThrowAsync<HttpRequestException>(() => client.GetStringAsync($"http://localhost:{port}/metadata"));
        ex.InnerException.ShouldBeOfType<OutboundFetchBlockedException>();
    }

    [Fact]
    public async Task ResponsesLargerThanTheLimit_AreNotRead()
    {
        await using var server = await StartServerAsync();
        var port = new Uri(Address(server)).Port;
        var options = new OutboundFetchOptions { AllowedHosts = ["localhost"], MaxResponseBytes = 1024 };
        using var client = Client(options);

        await Should.ThrowAsync<HttpRequestException>(() => client.GetByteArrayAsync($"http://localhost:{port}/big"));
    }

    private static HttpClient Client(OutboundFetchOptions options) =>
        new(OutboundFetch.CreateHandler(options)) { MaxResponseContentBufferSize = options.MaxResponseBytes };

    private static async Task<WebApplication> StartServerAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        app.MapGet("/ok", () => "ok");
        app.MapGet("/metadata", () => Results.Redirect("http://169.254.169.254/latest/meta-data/"));
        app.MapGet("/big", () => Results.Bytes(new byte[64 * 1024]));
        await app.StartAsync();
        return app;
    }

    private static string Address(WebApplication app) =>
        app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
}
