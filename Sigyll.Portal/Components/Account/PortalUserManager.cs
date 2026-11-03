#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Sigyll.Portal.Data;
using Sigyll.Portal.Services;
using Sigyll.ServiceDefaults;

namespace Sigyll.Portal.Components.Account;

/// <summary>
/// Portal accounts, with each change someone makes to their own sign-in security in the portal's audit trail
/// (<see cref="AuditedUserManager{TUser}"/>), as user.security-changed.
/// </summary>
public sealed class PortalUserManager(
    IUserStore<PortalUser> store,
    IOptions<IdentityOptions> optionsAccessor,
    IPasswordHasher<PortalUser> passwordHasher,
    IEnumerable<IUserValidator<PortalUser>> userValidators,
    IEnumerable<IPasswordValidator<PortalUser>> passwordValidators,
    ILookupNormalizer keyNormalizer,
    IdentityErrorDescriber errors,
    IServiceProvider services,
    ILogger<UserManager<PortalUser>> logger,
    IHttpContextAccessor httpContextAccessor,
    PortalAuditTrail audit)
    : AuditedUserManager<PortalUser>(store, optionsAccessor, passwordHasher, userValidators, passwordValidators,
        keyNormalizer, errors, services, logger, httpContextAccessor)
{
    protected override Task RecordAsync(string account, string detail) =>
        audit.RecordAsync(account, PortalAuditActions.SecurityChanged, account, detail);
}
