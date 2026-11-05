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
using Sigyll.Common.Security;
using Sigyll.Common.Services.Audit;
using Sigyll.Data;
using Sigyll.ServiceDefaults;

namespace Sigyll.Components.Account;

/// <summary>
/// Operator accounts, with each change an operator makes to their own sign-in security in the CA's audit trail
/// (<see cref="AuditedUserManager{TUser}"/>), as operator.security-changed.
/// </summary>
public sealed class OperatorUserManager(
    IUserStore<SigyllUser> store,
    IOptions<IdentityOptions> optionsAccessor,
    IPasswordHasher<SigyllUser> passwordHasher,
    IEnumerable<IUserValidator<SigyllUser>> userValidators,
    IEnumerable<IPasswordValidator<SigyllUser>> passwordValidators,
    ILookupNormalizer keyNormalizer,
    IdentityErrorDescriber errors,
    IServiceProvider services,
    ILogger<UserManager<SigyllUser>> logger,
    IHttpContextAccessor httpContextAccessor,
    AuditTrail audit)
    : AuditedUserManager<SigyllUser>(store, optionsAccessor, passwordHasher, userValidators, passwordValidators,
        keyNormalizer, errors, services, logger, httpContextAccessor)
{
    protected override Task RecordAsync(string account, string detail) =>
        audit.RecordAsync(new OperatorIdentity(account, new HashSet<Permission>()), AuditActions.OperatorSecurityChanged,
            AuditTarget.Operator(account), detail);
}
