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

/// <summary>The password step's outcome: Identity's result, and whether the operator must still present a passkey.</summary>
public sealed record PasswordStepResult(SignInResult Result, bool PasskeyRequired = false);

/// <summary>
/// The password step of operator sign-in. Failed passwords count towards lockout (<c>Auth:Session</c>), and sessions
/// never outlive the browser. A password alone is one factor: an operator with the authenticator app is asked for a
/// code next (Identity's two-factor step), and an operator whose second factor is a passkey (no authenticator app,
/// so Identity would ask for nothing more) must finish with the passkey. For them the password is checked without
/// signing in; signing in here would make the cookie handler redirect straight to the return URL.
/// </summary>
public sealed class OperatorSignIn(
    UserManager<SigyllUser> users,
    SignInManager<SigyllUser> signIn,
    IConfiguration configuration,
    IHostEnvironment environment,
    ILogger<OperatorSignIn> logger)
{
    public async Task<PasswordStepResult> PasswordAsync(string email, string password)
    {
        if (OperatorMfa.IsRequired(configuration, environment)
            && await users.FindByEmailAsync(email) is { } user
            && !await users.GetTwoFactorEnabledAsync(user)
            && (await users.GetPasskeysAsync(user)).Count > 0)
        {
            var result = await signIn.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);
            return new PasswordStepResult(result, PasskeyRequired: result.Succeeded);
        }

        return new PasswordStepResult(
            await signIn.PasswordSignInAsync(email, password, isPersistent: false, lockoutOnFailure: true));
    }

    /// <summary>
    /// Signs in with the passkey the browser returned. Null when no passkey prompt is pending for this browser: it
    /// timed out, or Sigyll restarted after the prompt began. Identity throws for that; the page asks for a retry.
    /// </summary>
    public async Task<SignInResult?> PasskeyAsync(string credentialJson)
    {
        try
        {
            return await signIn.PasskeySignInAsync(credentialJson);
        }
        catch (InvalidOperationException ex)
        {
            logger.LogWarning("Passkey sign-in refused: {Reason}", ex.Message);
            return null;
        }
    }

    /// <summary>Checks a passkey the browser created, to add it to the operator. Null as for <see cref="PasskeyAsync"/>.</summary>
    public async Task<PasskeyAttestationResult?> AttestPasskeyAsync(string credentialJson)
    {
        try
        {
            return await signIn.PerformPasskeyAttestationAsync(credentialJson);
        }
        catch (InvalidOperationException ex)
        {
            logger.LogWarning("Passkey not added: {Reason}", ex.Message);
            return null;
        }
    }
}
