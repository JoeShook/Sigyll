#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Aspire.Hosting.ApplicationModel;

namespace Sigyll.Vault.Hosting;

/// <summary>
/// Represents a HashiCorp Vault container resource for Aspire orchestration.
/// </summary>
public sealed class VaultResource(string name) : ContainerResource(name), IResourceWithConnectionString
{
    internal const string HttpEndpointName = "http";
    internal const int DefaultPort = 8200;

    private EndpointReference? _primaryEndpointReference;

    /// <summary>
    /// The primary HTTP endpoint for the Vault API.
    /// </summary>
    public EndpointReference PrimaryEndpoint =>
        _primaryEndpointReference ??= new EndpointReference(this, HttpEndpointName);

    /// <summary>
    /// The root token used for authentication in dev mode.
    /// </summary>
    public string RootToken { get; set; } = "root-token";

    /// <summary>
    /// Transit key specs to be created after Vault starts.
    /// </summary>
    internal List<TransitKeySpec> TransitKeys { get; } = [];

    /// <summary>
    /// Where the Transit engine is mounted (<see cref="VaultResourceBuilderExtensions.WithTransitMount"/>).
    /// </summary>
    internal string TransitMountPath { get; set; } = "transit";

    /// <summary>
    /// Earlier Transit mounts; the first that exists is moved to <see cref="TransitMountPath"/>, once, when nothing
    /// is mounted there yet.
    /// </summary>
    internal IReadOnlyList<string> TransitMoveFrom { get; set; } = [];

    /// <summary>
    /// What this application's Transit key names start with; its AppRole may use only those keys
    /// (<see cref="VaultResourceBuilderExtensions.WithTransitKeyPrefix"/>). Empty allows every key on the mount.
    /// </summary>
    internal string TransitKeyPrefix { get; set; } = "";

    /// <summary>
    /// AppRole to create for the app that uses this Vault (<see cref="VaultAppRoleExtensions.WithAppRole"/>).
    /// </summary>
    internal VaultAppRoleSpec? AppRole { get; set; }

    /// <summary>
    /// Completes once Vault is unsealed and its engines, keys and AppRole are configured.
    /// </summary>
    internal TaskCompletionSource Configured { get; set; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>
    /// Vault's address as seen from the AppHost, known once Vault is running.
    /// </summary>
    internal string? HostAddress { get; set; }

    /// <summary>
    /// When true, Vault runs in server mode with file-backed persistent storage.
    /// Init keys / root token are saved to <see cref="HostInitStatePath"/>.
    /// When false (default), Vault runs in dev mode (in-memory, wiped on every restart).
    /// </summary>
    internal bool IsPersistent { get; set; }

    /// <summary>
    /// Host filesystem path where init state (root token + unseal keys) is persisted.
    /// Only meaningful when <see cref="IsPersistent"/> is true.
    /// </summary>
    internal string? HostInitStatePath { get; set; }

    /// <summary>
    /// Connection string expression returning the Vault HTTP address.
    /// </summary>
    public ReferenceExpression ConnectionStringExpression =>
        ReferenceExpression.Create(
            $"{PrimaryEndpoint.Property(EndpointProperty.Scheme)}://{PrimaryEndpoint.Property(EndpointProperty.Host)}:{PrimaryEndpoint.Property(EndpointProperty.Port)}");
}
