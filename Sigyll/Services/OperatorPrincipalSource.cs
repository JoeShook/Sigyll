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
using Microsoft.AspNetCore.Components.Authorization;
using Sigyll.Common.Security;

namespace Sigyll.Services;

/// <summary>
/// The signed-in operator for the current scope. In a Blazor circuit (and during static
/// rendering) that is the component authentication state; for a minimal-API request it is the
/// request's user. A scope with neither, such as a background job, gets no principal and so no
/// permissions unless it runs as a system identity.
/// </summary>
public class OperatorPrincipalSource : IOperatorPrincipalSource
{
    private readonly AuthenticationStateProvider _authState;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public OperatorPrincipalSource(AuthenticationStateProvider authState, IHttpContextAccessor httpContextAccessor)
    {
        _authState = authState;
        _httpContextAccessor = httpContextAccessor;
    }

    public async ValueTask<ClaimsPrincipal?> GetPrincipalAsync()
    {
        try
        {
            return (await _authState.GetAuthenticationStateAsync()).User;
        }
        catch (InvalidOperationException)
        {
            // Not a component scope: the provider was never given an authentication state.
            return _httpContextAccessor.HttpContext?.User;
        }
    }
}
