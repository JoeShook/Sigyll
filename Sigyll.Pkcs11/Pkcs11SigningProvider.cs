#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Formats.Asn1;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Sigyll.Common.Data.Entities;
using Sigyll.Common.Services.Pqc;
using Sigyll.Common.Services.Signing;

namespace Sigyll.Pkcs11;

/// <summary>
/// Signs with keys held on a PKCS #11 token: an HSM in production, SoftHSM in development and CI. Keys are generated
/// on the token as sensitive and never extractable, and every signature is made there; Sigyll only ever sees public
/// keys and signatures. RSA signs with PKCS #1 v1.5; ECDSA signatures are returned DER-encoded.
/// </summary>
public sealed class Pkcs11SigningProvider : ISigningProvider, IKeyProtectionReporter, IDisposable
{
    public const string Name = "pkcs11";
    public string ProviderName => Name;

    private const string KeyLabelPrefix = "sigyll-";

    private readonly Pkcs11Options _options;
    private readonly ILogger<Pkcs11SigningProvider> _logger;
    // A PKCS #11 session is not safe for concurrent use; CA signing is infrequent, so one session serves them in turn.
    private readonly SemaphoreSlim _gate = new(1, 1);
    private IPkcs11Library? _library;
    private ISession? _session;
    private bool _isSoftHsm;

    public Pkcs11SigningProvider(IOptions<Pkcs11Options> options, ILogger<Pkcs11SigningProvider> logger)
    {
        _options = options.Value;
        _logger = logger;
        NativeLibraryNames.Register();
    }

    public async Task<SigningKeyReference> GenerateKeyAsync(string keyAlgorithm, int keySize, string? ecdsaCurve = null,
        string? purpose = null, CancellationToken ct = default)
    {
        if (PqcAlgorithms.IsPqc(keyAlgorithm))
            throw new NotSupportedException(PqcAlgorithms.RemoteBlockedMessage);
        if (keyAlgorithm.Equals("Ed25519", StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException("Ed25519 keys are not supported on PKCS #11 tokens; use the local signing provider for DID/VC keys.");

        var label = KeyLabelPrefix + Guid.NewGuid().ToString("N");
        var isEc = keyAlgorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase);

        await WithSessionAsync(session =>
        {
            var attrs = session.Factories.ObjectAttributeFactory;
            var id = System.Text.Encoding.ASCII.GetBytes(label);

            var publicTemplate = new List<IObjectAttribute>
            {
                attrs.Create(CKA.CKA_TOKEN, true),
                attrs.Create(CKA.CKA_PRIVATE, false),
                attrs.Create(CKA.CKA_LABEL, label),
                attrs.Create(CKA.CKA_ID, id),
                attrs.Create(CKA.CKA_VERIFY, true),
            };
            var privateTemplate = new List<IObjectAttribute>
            {
                attrs.Create(CKA.CKA_TOKEN, true),
                attrs.Create(CKA.CKA_PRIVATE, true),
                attrs.Create(CKA.CKA_LABEL, label),
                attrs.Create(CKA.CKA_ID, id),
                attrs.Create(CKA.CKA_SENSITIVE, true),
                attrs.Create(CKA.CKA_EXTRACTABLE, false),
                attrs.Create(CKA.CKA_SIGN, true),
            };

            CKM mechanism;
            if (isEc)
            {
                mechanism = CKM.CKM_EC_KEY_PAIR_GEN;
                publicTemplate.Add(attrs.Create(CKA.CKA_EC_PARAMS, EncodeCurveOid(ecdsaCurve)));
            }
            else
            {
                mechanism = CKM.CKM_RSA_PKCS_KEY_PAIR_GEN;
                publicTemplate.Add(attrs.Create(CKA.CKA_MODULUS_BITS, (ulong)keySize));
                publicTemplate.Add(attrs.Create(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 }));
            }

            session.GenerateKeyPair(session.Factories.MechanismFactory.Create(mechanism),
                publicTemplate, privateTemplate, out _, out _);
            return true;
        }, ct);

        _logger.LogInformation("Generated {Algorithm} key '{Label}' on PKCS #11 token '{Token}'",
            isEc ? $"ECDSA {ecdsaCurve ?? "nistP384"}" : $"RSA {keySize}", label, _options.TokenLabel);

        return new SigningKeyReference(Name, label, keyAlgorithm, keySize);
    }

    public Task<AsymmetricAlgorithm> GetPublicKeyAsync(SigningKeyReference keyRef, CancellationToken ct = default) =>
        WithSessionAsync<AsymmetricAlgorithm>(session =>
        {
            var publicKey = FindKey(session, keyRef.KeyIdentifier, CKO.CKO_PUBLIC_KEY);
            if (keyRef.KeyAlgorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
            {
                var values = session.GetAttributeValue(publicKey, [CKA.CKA_EC_PARAMS, CKA.CKA_EC_POINT]);
                return ImportEcPublicKey(values[0].GetValueAsByteArray(), values[1].GetValueAsByteArray());
            }

            var rsaValues = session.GetAttributeValue(publicKey, [CKA.CKA_MODULUS, CKA.CKA_PUBLIC_EXPONENT]);
            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = rsaValues[0].GetValueAsByteArray(),
                Exponent = rsaValues[1].GetValueAsByteArray(),
            });
            return rsa;
        }, ct);

    public Task<RawPublicKey> GetRawPublicKeyAsync(SigningKeyReference keyRef, CancellationToken ct = default) =>
        throw new NotSupportedException("Raw public keys for DID/VC are not available from PKCS #11 tokens; DID/VC code uses the local signing provider.");

    public Task<byte[]> SignDataAsync(byte[] data, HashAlgorithmName hashAlgorithm, SigningKeyReference keyRef,
        CancellationToken ct = default) =>
        WithSessionAsync(session =>
        {
            var privateKey = FindKey(session, keyRef.KeyIdentifier, CKO.CKO_PRIVATE_KEY);
            var mechanisms = session.Factories.MechanismFactory;

            if (keyRef.KeyAlgorithm.Equals("ECDSA", StringComparison.OrdinalIgnoreCase))
            {
                // CKM_ECDSA signs a digest and returns r || s; certificates and CRLs need the DER form.
                var digest = Hash(data, hashAlgorithm);
                var rawSignature = session.Sign(mechanisms.Create(CKM.CKM_ECDSA), privateKey, digest);
                return ConvertP1363ToDer(rawSignature);
            }

            var mechanism = hashAlgorithm.Name switch
            {
                "SHA256" => CKM.CKM_SHA256_RSA_PKCS,
                "SHA384" => CKM.CKM_SHA384_RSA_PKCS,
                "SHA512" => CKM.CKM_SHA512_RSA_PKCS,
                _ => throw new NotSupportedException($"Hash algorithm '{hashAlgorithm.Name}' is not supported for PKCS #11 RSA signing."),
            };
            return session.Sign(mechanisms.Create(mechanism), privateKey, data);
        }, ct);

    public CertSecurityLevel NewKeySecurityLevel =>
        _options.HardwareProtected && !IsSoftHsmToken() ? CertSecurityLevel.Fips1403 : CertSecurityLevel.CloudKms;

    /// <summary>
    /// A key counts as HSM-held only when the token is configured as a hardware HSM, is not SoftHSM, and the key's
    /// own attributes show it was generated on the token and can never leave it.
    /// </summary>
    public async Task<CertSecurityLevel> GetSecurityLevelAsync(SigningKeyReference keyRef, CancellationToken ct = default)
    {
        var flags = await GetPrivateKeyFlagsAsync(keyRef.KeyIdentifier, ct);
        return _options.HardwareProtected && !_isSoftHsm && flags.HeldOnToken
            ? CertSecurityLevel.Fips1403
            : CertSecurityLevel.CloudKms;
    }

    /// <summary>The private key's protection attributes, as the token reports them.</summary>
    internal Task<PrivateKeyFlags> GetPrivateKeyFlagsAsync(string keyLabel, CancellationToken ct = default) =>
        WithSessionAsync(session =>
        {
            var privateKey = FindKey(session, keyLabel, CKO.CKO_PRIVATE_KEY);
            var values = session.GetAttributeValue(privateKey,
                [CKA.CKA_LOCAL, CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE, CKA.CKA_NEVER_EXTRACTABLE]);
            return new PrivateKeyFlags(values[0].GetValueAsBool(), values[1].GetValueAsBool(),
                values[2].GetValueAsBool(), values[3].GetValueAsBool());
        }, ct);

    /// <summary>
    /// CKA_LOCAL (generated on the token), CKA_SENSITIVE, CKA_EXTRACTABLE and CKA_NEVER_EXTRACTABLE of a private key.
    /// </summary>
    internal readonly record struct PrivateKeyFlags(bool Local, bool Sensitive, bool Extractable, bool NeverExtractable)
    {
        public bool HeldOnToken => Local && Sensitive && !Extractable && NeverExtractable;
    }

    /// <summary>Destroys both halves of a key pair. Does nothing when the key is already gone.</summary>
    public Task DestroyKeyAsync(string keyLabel, CancellationToken ct = default) =>
        WithSessionAsync(session =>
        {
            var template = new List<IObjectAttribute> { session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, keyLabel) };
            foreach (var handle in session.FindAllObjects(template))
                session.DestroyObject(handle);
            _logger.LogInformation("Destroyed key '{Label}' on PKCS #11 token '{Token}'", keyLabel, _options.TokenLabel);
            return true;
        }, ct);

    public void Dispose()
    {
        _session?.Dispose();
        _library?.Dispose();
        _gate.Dispose();
    }

    // --- session handling ---

    private async Task<T> WithSessionAsync<T>(Func<ISession, T> action, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            return action(_session ??= OpenSession());
        }
        catch (Pkcs11Exception ex) when (ex.RV is CKR.CKR_SESSION_HANDLE_INVALID or CKR.CKR_SESSION_CLOSED
                                             or CKR.CKR_DEVICE_REMOVED or CKR.CKR_TOKEN_NOT_PRESENT)
        {
            // The token went away (HSM failover or restart): open a fresh session once and try again.
            _logger.LogWarning("PKCS #11 session lost ({Reason}); reopening", ex.RV);
            _session?.Dispose();
            _session = OpenSession();
            return action(_session);
        }
        finally
        {
            _gate.Release();
        }
    }

    private ISession OpenSession()
    {
        if (string.IsNullOrWhiteSpace(_options.LibraryPath) || string.IsNullOrWhiteSpace(_options.TokenLabel))
            throw new InvalidOperationException("PKCS #11 signing needs Pkcs11:LibraryPath and Pkcs11:TokenLabel.");
        if (string.IsNullOrEmpty(_options.UserPin))
            throw new InvalidOperationException("PKCS #11 signing needs the token's user PIN (Pkcs11:UserPin) from a secret store.");

        if (_library == null)
        {
            var factories = new Pkcs11InteropFactories();
            _library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, _options.LibraryPath, AppType.MultiThreaded);
        }

        var slot = _library.GetSlotList(SlotsType.WithTokenPresent)
            .FirstOrDefault(s => s.GetTokenInfo().Label.Trim() == _options.TokenLabel)
            ?? throw new InvalidOperationException($"No PKCS #11 token labelled '{_options.TokenLabel}' was found.");

        var tokenInfo = slot.GetTokenInfo();
        _isSoftHsm = IsSoftHsm(tokenInfo.ManufacturerId, tokenInfo.Model);
        if (_options.HardwareProtected && _isSoftHsm)
            _logger.LogWarning("Pkcs11:HardwareProtected is set, but token '{Token}' is SoftHSM; its keys are recorded as software-protected",
                _options.TokenLabel);

        var session = slot.OpenSession(SessionType.ReadWrite);
        try
        {
            session.Login(CKU.CKU_USER, _options.UserPin);
        }
        catch (Pkcs11Exception ex) when (ex.RV == CKR.CKR_USER_ALREADY_LOGGED_IN)
        {
            // Login state is shared by every session of this process; another session already logged in.
        }
        catch (Pkcs11Exception ex) when (ex.RV is CKR.CKR_PIN_INCORRECT or CKR.CKR_PIN_LOCKED)
        {
            session.Dispose();
            throw new InvalidOperationException($"The PKCS #11 token '{_options.TokenLabel}' refused the user PIN ({ex.RV}).", ex);
        }

        _logger.LogInformation("Opened PKCS #11 session on token '{Token}' ({Manufacturer} {Model})",
            _options.TokenLabel, tokenInfo.ManufacturerId.Trim(), tokenInfo.Model.Trim());
        return session;
    }

    private bool IsSoftHsmToken()
    {
        // Configuration alone answers before any session is open; once one is, the token's own description counts.
        if (_session == null)
        {
            try
            {
                _gate.Wait();
                try { _session ??= OpenSession(); }
                finally { _gate.Release(); }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not open the PKCS #11 token to check what it is; treating its keys as software-protected");
                return true;
            }
        }
        return _isSoftHsm;
    }

    internal static bool IsSoftHsm(string manufacturer, string model) =>
        manufacturer.Contains("SoftHSM", StringComparison.OrdinalIgnoreCase)
        || model.Contains("SoftHSM", StringComparison.OrdinalIgnoreCase);

    private static IObjectHandle FindKey(ISession session, string label, CKO keyClass)
    {
        var attrs = session.Factories.ObjectAttributeFactory;
        var found = session.FindAllObjects([attrs.Create(CKA.CKA_CLASS, keyClass), attrs.Create(CKA.CKA_LABEL, label)]);
        return found.Count switch
        {
            1 => found[0],
            0 => throw new InvalidOperationException($"Signing key not found on the PKCS #11 token: '{label}'."),
            _ => throw new InvalidOperationException($"More than one key on the PKCS #11 token is labelled '{label}'."),
        };
    }

    // --- encoding helpers ---

    internal static byte[] EncodeCurveOid(string? ecdsaCurve)
    {
        var oid = ecdsaCurve?.ToLowerInvariant() switch
        {
            "nistp256" => "1.2.840.10045.3.1.7",
            "nistp521" => "1.3.132.0.35",
            _ => "1.3.132.0.34", // nistP384, Sigyll's default curve
        };
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteObjectIdentifier(oid);
        return writer.Encode();
    }

    /// <summary>
    /// Builds an ECDsa public key from CKA_EC_PARAMS (the curve's DER OID) and CKA_EC_POINT, which tokens return either
    /// DER-wrapped in an OCTET STRING (as PKCS #11 specifies) or as the bare uncompressed point.
    /// </summary>
    internal static ECDsa ImportEcPublicKey(byte[] ecParams, byte[] ecPoint)
    {
        var curve = ECCurve.CreateFromValue(AsnDecoder.ReadObjectIdentifier(ecParams, AsnEncodingRules.DER, out _));
        using var probe = ECDsa.Create(curve);
        var coordinateLength = (probe.KeySize + 7) / 8;

        var point = ecPoint;
        if (ecPoint.Length != 1 + 2 * coordinateLength)
            point = AsnDecoder.ReadOctetString(ecPoint, AsnEncodingRules.DER, out _);
        if (point.Length != 1 + 2 * coordinateLength || point[0] != 0x04)
            throw new InvalidOperationException("The token returned an EC point that is not an uncompressed point on the key's curve.");

        return ECDsa.Create(new ECParameters
        {
            Curve = curve,
            Q = new ECPoint
            {
                X = point[1..(1 + coordinateLength)],
                Y = point[(1 + coordinateLength)..],
            },
        });
    }

    internal static byte[] ConvertP1363ToDer(byte[] signature)
    {
        var half = signature.Length / 2;
        var r = new BigInteger(1, signature, 0, half);
        var s = new BigInteger(1, signature, half, half);
        return new DerSequence(new DerInteger(r), new DerInteger(s)).GetEncoded();
    }

    private static byte[] Hash(byte[] data, HashAlgorithmName hashAlgorithm) => hashAlgorithm.Name switch
    {
        "SHA256" => SHA256.HashData(data),
        "SHA384" => SHA384.HashData(data),
        "SHA512" => SHA512.HashData(data),
        _ => throw new NotSupportedException($"Hash algorithm '{hashAlgorithm.Name}' is not supported for PKCS #11 ECDSA signing."),
    };
}
