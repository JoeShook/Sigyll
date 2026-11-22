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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sigyll.AppHost;

/// <summary>
/// Tells an Omarchy session how to start Docker when Aspire cannot reach it.
/// </summary>
/// <remarks>
/// Windows and macOS launch Docker Desktop from the <c>docker</c> command. Omarchy runs <c>dockerd</c> as a systemd
/// service and leaves the user out of the <c>docker</c> group, so the AppHost gets "permission denied" on
/// <c>/var/run/docker.sock</c> and the engine stays stopped. The dashboard shows the script to paste into a terminal.
/// </remarks>
internal static class OmarchyDockerNotice
{
    public static void Register(IDistributedApplicationBuilder builder)
    {
        if (builder.ExecutionContext.IsPublishMode || !IsOmarchy())
            return;

        var runtime = Environment.GetEnvironmentVariable("ASPIRE_CONTAINER_RUNTIME");
        if (!string.IsNullOrWhiteSpace(runtime) && !runtime.Equals("docker", StringComparison.OrdinalIgnoreCase))
            return;

        var probe = ProbeDocker();
        if (probe.Ok)
            return;

        var permissionDenied = probe.Error.Contains("permission denied", StringComparison.OrdinalIgnoreCase);
        var script = StartScript(permissionDenied);
        var message = DashboardMessage(permissionDenied);

        Console.Error.WriteLine(message);
        Console.Error.WriteLine(script);

        var resource = new NoticeResource("docker-engine");
        builder.AddResource(resource)
            .ExcludeFromManifest()
            .WithInitialState(new CustomResourceSnapshot
            {
                ResourceType = "Docker",
                State = new ResourceStateSnapshot("sudo systemctl start docker", KnownResourceStateStyles.Warn),
                CreationTimeStamp = DateTime.UtcNow,
                Properties =
                [
                    new ResourcePropertySnapshot("start-script", script)
                    {
                        DisplayName = "Start script",
                    },
                ],
            })
            .WithCommand(
                "show-start-script",
                "Show start script",
                _ => Task.FromResult(CommandResults.Success(
                    "Copy this into a terminal, then start the AppHost again.",
                    MarkdownMessage(message, script),
                    CommandResultFormat.Markdown,
                    displayImmediately: true)),
                new CommandOptions
                {
                    Description = "Commands that start Docker for this AppHost",
                    IconName = "Copy",
                });

        builder.OnBeforeStart((e, _) =>
        {
            e.Services.GetRequiredService<ResourceLoggerService>().GetLogger(resource)
                .LogWarning("{Message}{NewLine}{Script}", message, Environment.NewLine, script);

            var interaction = e.Services.GetService<IInteractionService>();
            if (interaction is { IsAvailable: true })
            {
                // Queue only. Awaiting here deadlocks startup: the dialog needs the dashboard, and the
                // dashboard is not listening until this callback returns. AfterResourcesCreated is too late
                // when Docker is down, because that event waits for the containers that cannot start.
                var stopping = e.Services.GetRequiredService<IHostApplicationLifetime>().ApplicationStopping;
                notice = ShowDashboardMessageAsync(interaction, message, script, stopping);
            }

            return Task.CompletedTask;
        });
    }

    private static Task? notice;

    private static async Task ShowDashboardMessageAsync(
        IInteractionService interaction, string message, string script, CancellationToken cancellationToken)
    {
        try
        {
            await interaction.PromptMessageBoxAsync(
                "Docker is not running",
                MarkdownMessage(message, script),
                new MessageBoxInteractionOptions
                {
                    Intent = MessageIntent.Warning,
                    EnableMessageMarkdown = true,
                    PrimaryButtonText = "Close",
                },
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[sigyll] Could not show the Docker notice in the dashboard: {ex.Message}");
        }
    }

    private static string StartScript(bool permissionDenied) =>
        permissionDenied
            ? """
              sudo systemctl start docker
              sudo docker info
              omarchy setup security sudoless docker
              """
            : """
              sudo systemctl start docker
              sudo docker info
              """;

    private static string DashboardMessage(bool permissionDenied) =>
        permissionDenied
            ? """
              Aspire does not start Docker on Omarchy. Windows and macOS launch Docker Desktop. Here the engine is the dockerd service, and this user cannot open /var/run/docker.sock.

              Copy the script below into a terminal. sudo docker info checks the engine. Aspire connects as your user, without sudo, so the AppHost stays blocked until docker info works with no sudo. omarchy setup security sudoless docker adds you to the docker group and asks you to reboot. That group is root-equivalent.
              """
            : """
              Aspire does not start Docker on Omarchy. Windows and macOS launch Docker Desktop. Here the engine is the dockerd service, and it is stopped.

              Copy the script below into a terminal. After sudo docker info succeeds, start the AppHost again. If docker info without sudo then says permission denied, run: omarchy setup security sudoless docker
              """;

    private static string MarkdownMessage(string message, string script) =>
        message + "\n\n```bash\n" + script + "\n```";

    private static bool IsOmarchy()
    {
        if (!OperatingSystem.IsLinux() || !File.Exists("/etc/os-release"))
            return false;

        foreach (var line in File.ReadLines("/etc/os-release"))
        {
            if (!line.StartsWith("ID=", StringComparison.Ordinal))
                continue;

            return line["ID=".Length..].Trim().Trim('"') == "omarchy";
        }

        return false;
    }

    private static DockerProbe ProbeDocker()
    {
        var start = new ProcessStartInfo("docker", "info")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        try
        {
            using var process = Process.Start(start);
            if (process is null)
                return DockerProbe.Failed("docker info did not start");

            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(TimeSpan.FromSeconds(8)))
            {
                process.Kill(entireProcessTree: true);
                return DockerProbe.Failed("docker info timed out");
            }

            if (process.ExitCode == 0)
                return DockerProbe.Success();

            var text = error.Result.Trim();
            if (text.Length == 0)
                text = output.Result.Trim();
            return DockerProbe.Failed(text.Length == 0 ? "docker info failed" : text);
        }
        catch (Win32Exception ex)
        {
            return DockerProbe.Failed(ex.Message);
        }
    }

    private readonly record struct DockerProbe(bool Ok, string Error)
    {
        public static DockerProbe Success() => new(true, "");
        public static DockerProbe Failed(string error) => new(false, error);
    }

    private sealed class NoticeResource(string name) : Resource(name);
}
