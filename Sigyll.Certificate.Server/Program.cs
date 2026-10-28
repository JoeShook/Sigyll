#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.FileProviders;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

Log.Information("Starting Sigyll Certificate Server");

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Host.UseSerilog((ctx, lc) => lc
        .WriteTo.Console(
            outputTemplate:
            "[{Timestamp:HH:mm:ss} {Level}][{ThreadId:d}] {SourceContext} {Message:lj}{NewLine}{Exception}",
            theme: AnsiConsoleTheme.Code)
        .MinimumLevel.Information()
        .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
        .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
        .Enrich.FromLogContext()
        .Enrich.WithThreadId());

    builder.Services.AddDirectoryBrowser();

    var app = builder.Build();

    // A lab tool for browsing what Sigyll has published; the folders can be listed. Only certificates and
    // CRLs are served, though: anything else under wwwroot (a half-written .tmp file, a stray upload) is a 404.
    var provider = new FileExtensionContentTypeProvider(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        [".cer"] = "application/pkix-cert",
        [".crt"] = "application/pkix-cert",
        [".crl"] = "application/pkix-crl",
        [".p7c"] = "application/pkcs7-mime",
        [".pem"] = "application/x-pem-file",
    });

    app.UseSerilogRequestLogging();

    app.Use(async (context, next) =>
    {
        if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method))
        {
            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            context.Response.Headers.Allow = "GET, HEAD";
            return;
        }

        var headers = context.Response.Headers;
        headers.XContentTypeOptions = "nosniff";
        // The directory listing page uses inline styles and nothing else.
        headers.ContentSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'";
        headers["Referrer-Policy"] = "no-referrer";
        await next();
    });

    app.UseStaticFiles(new StaticFileOptions
    {
        ContentTypeProvider = provider
    });

    app.UseDirectoryBrowser(new DirectoryBrowserOptions
    {
        FileProvider = new PhysicalFileProvider(builder.Environment.WebRootPath)
    });

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Unhandled exception");
}
finally
{
    Log.CloseAndFlush();
}
