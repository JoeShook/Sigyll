#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Claims;

namespace Sigyll.Common.Security;

/// <summary>Who is performing an operation and what they may do.</summary>
public sealed record OperatorIdentity(string Name, IReadOnlySet<Permission> Permissions, bool IsSystem = false)
{
    /// <summary>No one: holds no permissions. The identity of any scope nobody has claimed.</summary>
    public static readonly OperatorIdentity Anonymous = new("(anonymous)", new HashSet<Permission>());

    /// <summary>Background work (scheduler) and machine clients (the RA): a named, fixed set of permissions.</summary>
    public static OperatorIdentity System(string name, params Permission[] permissions) =>
        new(name, permissions.ToHashSet(), IsSystem: true);

    /// <summary>A signed-in operator; permissions come from their roles.</summary>
    public static OperatorIdentity FromPrincipal(ClaimsPrincipal? principal)
    {
        if (principal?.Identity?.IsAuthenticated != true)
            return Anonymous;

        var roles = principal.FindAll(ClaimTypes.Role).Select(c => c.Value);
        return new OperatorIdentity(
            principal.Identity.Name ?? "(unnamed)",
            RolePermissions.For(roles).ToHashSet());
    }

    public bool Has(Permission permission) => Permissions.Contains(permission);
}

/// <summary>
/// The operator on whose behalf the current scope runs. Every service that reads or changes CA
/// state asks this before it acts; see <see cref="OperatorContextExtensions.DemandAsync"/>.
/// </summary>
public interface IOperatorContext
{
    ValueTask<OperatorIdentity> GetCurrentAsync();
}

/// <summary>
/// Supplies the signed-in user for the current scope (a Blazor circuit or an HTTP request).
/// Implemented by the host, which knows about authentication; returns null when there is none.
/// </summary>
public interface IOperatorPrincipalSource
{
    ValueTask<ClaimsPrincipal?> GetPrincipalAsync();
}

/// <summary>
/// Scoped <see cref="IOperatorContext"/>. A system actor set with <see cref="RunAs"/> wins;
/// otherwise the host's signed-in user; otherwise <see cref="OperatorIdentity.Anonymous"/>, so a
/// scope that nobody claimed can do nothing.
/// </summary>
public sealed class OperatorContext : IOperatorContext
{
    private readonly IOperatorPrincipalSource? _principalSource;
    private OperatorIdentity? _runAs;

    public OperatorContext(IOperatorPrincipalSource? principalSource = null)
    {
        _principalSource = principalSource;
    }

    /// <summary>Runs the rest of this scope as <paramref name="identity"/>. Set once, before any service call.</summary>
    public void RunAs(OperatorIdentity identity)
    {
        if (_runAs != null && _runAs != identity)
            throw new InvalidOperationException($"This scope already runs as '{_runAs.Name}'.");
        _runAs = identity;
    }

    public async ValueTask<OperatorIdentity> GetCurrentAsync()
    {
        if (_runAs != null)
            return _runAs;
        if (_principalSource == null)
            return OperatorIdentity.Anonymous;
        return OperatorIdentity.FromPrincipal(await _principalSource.GetPrincipalAsync());
    }
}

/// <summary>Thrown when the current operator lacks the permission an operation requires.</summary>
public sealed class OperatorAccessDeniedException : UnauthorizedAccessException
{
    public OperatorAccessDeniedException(string actor, IReadOnlyCollection<Permission> required)
        : base($"'{actor}' is not allowed to do this (requires {string.Join(" or ", required)}).")
    {
        Actor = actor;
        Required = required;
    }

    public string Actor { get; }
    public IReadOnlyCollection<Permission> Required { get; }
}

public static class OperatorContextExtensions
{
    /// <summary>
    /// Returns the current operator if they hold any of <paramref name="anyOf"/>; otherwise throws
    /// <see cref="OperatorAccessDeniedException"/>. Call it first in every public service method.
    /// </summary>
    public static async ValueTask<OperatorIdentity> DemandAsync(this IOperatorContext context, params Permission[] anyOf)
    {
        var identity = await context.GetCurrentAsync();
        if (!anyOf.Any(identity.Has))
            throw new OperatorAccessDeniedException(identity.Name, anyOf);
        return identity;
    }
}

/// <summary>
/// Marks a public member of a CA service that deliberately does not check the operator, with
/// the reason. The service-boundary tests require either this or a permission check.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public sealed class NoOperatorCheckAttribute(string reason) : Attribute
{
    public string Reason { get; } = reason;
}
