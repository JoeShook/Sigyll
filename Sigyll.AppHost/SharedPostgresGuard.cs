#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;

namespace Sigyll.AppHost;

/// <summary>
/// Lets this AppHost share a persistent PostgreSQL container with other AppHosts without recreating it.
/// </summary>
/// <remarks>
/// Aspire reuses a persistent container only while the container description it generates is identical, and
/// that description changes between Aspire versions. AppHosts that share one container therefore stamp it with
/// their Aspire version in an environment variable (an environment variable, not a label: Aspire compares the
/// environment when deciding to reuse). When <c>Postgres:AspireVersionVariable</c> names that variable, this
/// AppHost stamps the container the same way, and stops before starting if the container belongs to a newer
/// Aspire version, instead of recreating it under the AppHosts already on that version.
/// </remarks>
internal static class SharedPostgresGuard
{
    public static Version AspireVersion { get; } = ReadAspireVersion();

    public static IResourceBuilder<PostgresServerResource> WithSharedAspireVersion(
        this IResourceBuilder<PostgresServerResource> postgres, string containerName, string? versionVariable)
    {
        if (string.IsNullOrWhiteSpace(versionVariable) || postgres.ApplicationBuilder.ExecutionContext.IsPublishMode)
            return postgres;

        var existing = ReadContainerVersion(containerName, versionVariable);
        if (existing is not null && existing > AspireVersion)
        {
            Console.Error.WriteLine(
                $"""

                [sigyll] {containerName} belongs to Aspire {existing}; this AppHost is on Aspire {AspireVersion}.
                [sigyll] Starting would recreate the shared database container under the AppHosts already on {existing}.
                [sigyll] Upgrade Sigyll.AppHost to Aspire {existing}, then start again.

                """);
            Environment.Exit(1);
        }

        if (existing is not null && existing < AspireVersion)
        {
            Console.WriteLine(
                $"[sigyll] {containerName} moves from Aspire {existing} to {AspireVersion}; Aspire recreates it once " +
                "(the data stays on its volume).");
        }

        return postgres.WithEnvironment(versionVariable, AspireVersion.ToString());
    }

    private static Version ReadAspireVersion()
    {
        // "13.6.1+<commit>" or "13.7.0-preview.1+<commit>": keep the numeric part.
        var informational = typeof(DistributedApplication).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0";
        return Version.Parse(informational.Split('+', '-')[0]);
    }

    /// <summary>The version recorded on the existing container; null when there is none or it can't be read.</summary>
    private static Version? ReadContainerVersion(string containerName, string variable)
    {
        var runtime = Environment.GetEnvironmentVariable("ASPIRE_CONTAINER_RUNTIME") is { Length: > 0 } r ? r : "docker";
        var start = new ProcessStartInfo(runtime) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var arg in new[] { "inspect", containerName, "--format", "{{range .Config.Env}}{{println .}}{{end}}" })
            start.ArgumentList.Add(arg);

        try
        {
            using var process = Process.Start(start);
            if (process is null)
                return null;

            var output = process.StandardOutput.ReadToEndAsync();
            _ = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(TimeSpan.FromSeconds(20)))
            {
                process.Kill(entireProcessTree: true);
                return null;
            }

            var value = process.ExitCode == 0
                ? output.Result.Split('\n').Select(line => line.Trim())
                    .FirstOrDefault(line => line.StartsWith($"{variable}="))?[(variable.Length + 1)..]
                : null;
            return Version.TryParse(value, out var version) ? version : null;
        }
        catch (Win32Exception)
        {
            return null;
        }
    }
}
