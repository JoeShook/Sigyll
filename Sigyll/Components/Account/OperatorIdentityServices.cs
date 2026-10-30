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
using Sigyll.Data;

namespace Sigyll.Components.Account;

/// <summary>
/// Operator accounts: Identity over <see cref="SigyllAuthDbContext"/> with passkeys, the sign-in cookies, lockout and
/// session limits (<c>Auth:Session</c>), the password step of sign-in, and the audit of every sign-in
/// (<see cref="OperatorSignInManager"/>). The host registers the database contexts and the audit trail; the tests
/// register the same services over in-memory ones.
/// </summary>
public static class OperatorIdentityServices
{
    public static IServiceCollection AddOperatorIdentity(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddAuthentication(options =>
            {
                options.DefaultScheme = IdentityConstants.ApplicationScheme;
                options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
            })
            .AddIdentityCookies();
        // Lockout, idle timeout and maximum session length (Auth:Session).
        services.AddOperatorSession(configuration);

        services.AddIdentityCore<SigyllUser>(options =>
            {
                // Operator accounts are created by an Admin — no self-registration, no email loop.
                options.SignIn.RequireConfirmedAccount = false;
                // Required for the AspNetUserPasskeys store (.NET 10 passkeys).
                options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
            })
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<SigyllAuthDbContext>()
            .AddSignInManager<OperatorSignInManager>()
            .AddDefaultTokenProviders();

        // Pin the passkey Relying Party ID explicitly. A CA must not infer the RP ID from the
        // host header (credential-scoping risk).
        services.Configure<IdentityPasskeyOptions>(options =>
        {
            options.ServerDomain = configuration["Auth:Passkey:ServerDomain"];
        });

        services.AddScoped<OperatorSignIn>();
        return services;
    }
}
