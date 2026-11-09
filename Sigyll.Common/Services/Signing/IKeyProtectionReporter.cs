#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Sigyll.Common.Data.Entities;

namespace Sigyll.Common.Services.Signing;

/// <summary>
/// Implemented by a remote signing provider that can say how its keys are protected, so Sigyll records where a key
/// really lives instead of assuming, and a trust domain that requires HSM-held CA keys can check before and after
/// a key is made.
/// </summary>
public interface IKeyProtectionReporter
{
    /// <summary>How a key this provider generates next will be protected, from its configuration.</summary>
    CertSecurityLevel NewKeySecurityLevel { get; }

    /// <summary>How an existing key is protected, as the key service reports it.</summary>
    Task<CertSecurityLevel> GetSecurityLevelAsync(SigningKeyReference keyRef, CancellationToken ct = default);
}
