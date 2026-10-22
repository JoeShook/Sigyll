#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sigyll.Common.Services.Pqc;

/// <summary>
/// NIST PQC parameter sets Sigyll can issue, plus the composite ML-DSA combinations
/// shipped with .NET 10 (draft-ietf-lamps-pq-composite-sigs). Identifiers match the
/// names <see cref="MLDsaAlgorithm"/>, <see cref="SlhDsaAlgorithm"/>, <see cref="MLKemAlgorithm"/>
/// and <see cref="CompositeMLDsaAlgorithm"/> report, so a stored <c>KeyAlgorithm</c>
/// round-trips with the certificate itself.
/// </summary>
public static class PqcAlgorithms
{
    public const string RemoteBlockedMessage =
        "Post-quantum keys are local only. Vault Transit and GCP KMS do not implement ML-DSA, SLH-DSA, ML-KEM, or composite ML-DSA.";

    public const string PlatformRequirement =
        "This host cannot use that algorithm. .NET 10 post-quantum cryptography requires OpenSSL 3.5 or newer, or Windows CNG with PQC support.";

    public static readonly string[] ProfileFamilies =
        ["RSA", "ECDSA", "ML-DSA", "SLH-DSA", "ML-KEM", "Composite ML-DSA"];

    private static readonly PqcAlgorithmInfo[] All =
    [
        A("ML-DSA", "ML-DSA-44", "ML-DSA-44 (NIST level 2)", 44, canSign: true),
        A("ML-DSA", "ML-DSA-65", "ML-DSA-65 (NIST level 3)", 65, canSign: true),
        A("ML-DSA", "ML-DSA-87", "ML-DSA-87 (NIST level 5)", 87, canSign: true),

        A("SLH-DSA", "SLH-DSA-SHA2-128s", "SLH-DSA SHA2-128s", 128, canSign: true),
        A("SLH-DSA", "SLH-DSA-SHA2-128f", "SLH-DSA SHA2-128f", 128, canSign: true),
        A("SLH-DSA", "SLH-DSA-SHA2-192s", "SLH-DSA SHA2-192s", 192, canSign: true),
        A("SLH-DSA", "SLH-DSA-SHA2-192f", "SLH-DSA SHA2-192f", 192, canSign: true),
        A("SLH-DSA", "SLH-DSA-SHA2-256s", "SLH-DSA SHA2-256s", 256, canSign: true),
        A("SLH-DSA", "SLH-DSA-SHA2-256f", "SLH-DSA SHA2-256f", 256, canSign: true),
        A("SLH-DSA", "SLH-DSA-SHAKE-128s", "SLH-DSA SHAKE-128s", 128, canSign: true),
        A("SLH-DSA", "SLH-DSA-SHAKE-128f", "SLH-DSA SHAKE-128f", 128, canSign: true),
        A("SLH-DSA", "SLH-DSA-SHAKE-192s", "SLH-DSA SHAKE-192s", 192, canSign: true),
        A("SLH-DSA", "SLH-DSA-SHAKE-192f", "SLH-DSA SHAKE-192f", 192, canSign: true),
        A("SLH-DSA", "SLH-DSA-SHAKE-256s", "SLH-DSA SHAKE-256s", 256, canSign: true),
        A("SLH-DSA", "SLH-DSA-SHAKE-256f", "SLH-DSA SHAKE-256f", 256, canSign: true),

        A("ML-KEM", "ML-KEM-512", "ML-KEM-512 (NIST level 1)", 512, canSign: false),
        A("ML-KEM", "ML-KEM-768", "ML-KEM-768 (NIST level 3)", 768, canSign: false),
        A("ML-KEM", "ML-KEM-1024", "ML-KEM-1024 (NIST level 5)", 1024, canSign: false),

        A("Composite ML-DSA", "MLDSA44-RSA2048-PSS-SHA256", "ML-DSA-44 + RSA-2048 PSS", 44, canSign: true),
        A("Composite ML-DSA", "MLDSA44-RSA2048-PKCS15-SHA256", "ML-DSA-44 + RSA-2048 PKCS#1 v1.5", 44, canSign: true),
        A("Composite ML-DSA", "MLDSA44-Ed25519-SHA512", "ML-DSA-44 + Ed25519", 44, canSign: true),
        A("Composite ML-DSA", "MLDSA44-ECDSA-P256-SHA256", "ML-DSA-44 + ECDSA P-256", 44, canSign: true),
        A("Composite ML-DSA", "MLDSA65-RSA3072-PSS-SHA512", "ML-DSA-65 + RSA-3072 PSS", 65, canSign: true),
        A("Composite ML-DSA", "MLDSA65-RSA3072-PKCS15-SHA512", "ML-DSA-65 + RSA-3072 PKCS#1 v1.5", 65, canSign: true),
        A("Composite ML-DSA", "MLDSA65-RSA4096-PSS-SHA512", "ML-DSA-65 + RSA-4096 PSS", 65, canSign: true),
        A("Composite ML-DSA", "MLDSA65-RSA4096-PKCS15-SHA512", "ML-DSA-65 + RSA-4096 PKCS#1 v1.5", 65, canSign: true),
        A("Composite ML-DSA", "MLDSA65-ECDSA-P256-SHA512", "ML-DSA-65 + ECDSA P-256", 65, canSign: true),
        A("Composite ML-DSA", "MLDSA65-ECDSA-P384-SHA512", "ML-DSA-65 + ECDSA P-384", 65, canSign: true),
        A("Composite ML-DSA", "MLDSA65-ECDSA-brainpoolP256r1-SHA512", "ML-DSA-65 + brainpoolP256r1", 65, canSign: true),
        A("Composite ML-DSA", "MLDSA65-Ed25519-SHA512", "ML-DSA-65 + Ed25519", 65, canSign: true),
        A("Composite ML-DSA", "MLDSA87-ECDSA-P384-SHA512", "ML-DSA-87 + ECDSA P-384", 87, canSign: true),
        A("Composite ML-DSA", "MLDSA87-ECDSA-brainpoolP384r1-SHA512", "ML-DSA-87 + brainpoolP384r1", 87, canSign: true),
        A("Composite ML-DSA", "MLDSA87-ECDSA-P521-SHA512", "ML-DSA-87 + ECDSA P-521", 87, canSign: true),
        A("Composite ML-DSA", "MLDSA87-Ed448-SHAKE256", "ML-DSA-87 + Ed448", 87, canSign: true),
        A("Composite ML-DSA", "MLDSA87-RSA3072-PSS-SHA512", "ML-DSA-87 + RSA-3072 PSS", 87, canSign: true),
        A("Composite ML-DSA", "MLDSA87-RSA4096-PSS-SHA512", "ML-DSA-87 + RSA-4096 PSS", 87, canSign: true),
    ];

    private static readonly string[] CsrAlgorithmList =
        ["RSA", "ECDSA", .. All.Where(a => a.CanSign).Select(a => a.Id)];

    public static IReadOnlyList<PqcAlgorithmInfo> ParameterSets => All;

    /// <summary>RSA, ECDSA, and every PQC signature parameter set. ML-KEM is omitted: it cannot sign a CSR.</summary>
    public static IReadOnlyList<string> CsrAlgorithms => CsrAlgorithmList;

    public static bool IsPqc(string? algorithm) => Canonicalize(algorithm, 0) != null
        || (!string.IsNullOrWhiteSpace(algorithm) && (
            algorithm.StartsWith("ML-DSA", StringComparison.OrdinalIgnoreCase)
            || algorithm.StartsWith("SLH-DSA", StringComparison.OrdinalIgnoreCase)
            || algorithm.StartsWith("ML-KEM", StringComparison.OrdinalIgnoreCase)
            || algorithm.StartsWith("MLDSA", StringComparison.OrdinalIgnoreCase)));

    public static bool IsKem(string? algorithm, int keySize = 0)
    {
        var id = Canonicalize(algorithm, keySize);
        return id != null && TryGet(id, out var info) && info.Family == "ML-KEM";
    }

    public static bool IsProfileFamily(string? family) =>
        family is "ML-DSA" or "SLH-DSA" or "ML-KEM" or "Composite ML-DSA";

    public static IReadOnlyList<PqcAlgorithmInfo> ForFamily(string family) =>
        All.Where(a => a.Family.Equals(family, StringComparison.OrdinalIgnoreCase)).ToArray();

    public static bool TryGet(string? id, out PqcAlgorithmInfo info)
    {
        if (!string.IsNullOrWhiteSpace(id))
        {
            foreach (var candidate in All)
            {
                if (candidate.Id.Equals(id, StringComparison.OrdinalIgnoreCase))
                {
                    info = candidate;
                    return true;
                }
            }
        }

        info = null!;
        return false;
    }

    public static PqcAlgorithmInfo Require(string id) =>
        TryGet(id, out var info)
            ? info
            : throw new ArgumentException($"Unknown post-quantum algorithm '{id}'.", nameof(id));

    public static string LabelOf(string id) =>
        TryGet(id, out var info) ? info.Label : id;

    /// <summary>
    /// Resolves a stored algorithm. Accepts a full id ("ML-DSA-65") or a family plus size ("ML-DSA", 65).
    /// </summary>
    public static string? Canonicalize(string? algorithm, int keySize)
    {
        if (string.IsNullOrWhiteSpace(algorithm)) return null;
        if (TryGet(algorithm, out var exact)) return exact.Id;
        if (keySize > 0 && TryGet($"{algorithm}-{keySize}", out var sized)) return sized.Id;
        return null;
    }

    public static string? UnsupportedReason(string? algorithm, int keySize = 0)
    {
        var id = Canonicalize(algorithm, keySize);
        if (id == null)
        {
            return IsPqc(algorithm)
                ? $"Unknown post-quantum algorithm '{algorithm}'."
                : null;
        }

        return IsSupported(id) ? null : $"{LabelOf(id)} is not available here. {PlatformRequirement}";
    }

    public static bool IsSupported(string id)
    {
        if (!TryGet(id, out var info)) return false;
        return info.Family switch
        {
            "ML-DSA" => MLDsa.IsSupported,
            "SLH-DSA" => SlhDsa.IsSupported,
            "ML-KEM" => MLKem.IsSupported,
            "Composite ML-DSA" => CompositeMLDsa.IsSupported,
            _ => false
        };
    }

    public static string ParameterHelp(string family) => family switch
    {
        "ML-DSA" => "Pure ML-DSA (FIPS 204). The hash is inside the signature; the profile hash is not used. ML-DSA-87 is the CA default.",
        "SLH-DSA" => "Pure SLH-DSA (FIPS 205). \"s\" is the small signature, \"f\" is the fast one. Signatures are large.",
        "ML-KEM" => "ML-KEM (FIPS 203) encapsulates a shared secret. It cannot sign, so it cannot be a CA. Key usage should be Key Agreement.",
        "Composite ML-DSA" => "Hybrid signature: ML-DSA and a classical algorithm, both must verify (draft-ietf-lamps-pq-composite-sigs).",
        _ => ""
    };

    public static (string Algorithm, int KeySize) DescribeCertificate(X509Certificate2 cert)
    {
        using (var ml = cert.GetMLDsaPublicKey())
        {
            if (ml != null)
                return (ml.Algorithm.Name, ParameterSize(ml.Algorithm.Name, 44));
        }

        using (var slh = cert.GetSlhDsaPublicKey())
        {
            if (slh != null)
                return (slh.Algorithm.Name, SlhSecurityBits(slh.Algorithm.Name));
        }

        using (var kem = cert.GetMLKemPublicKey())
        {
            if (kem != null)
                return (kem.Algorithm.Name, ParameterSize(kem.Algorithm.Name, 768));
        }

        using (var composite = cert.GetCompositeMLDsaPublicKey())
        {
            if (composite != null)
                return (composite.Algorithm.Name, CompositeParameter(composite.Algorithm.Name));
        }

        using (var rsa = cert.GetRSAPublicKey())
        {
            if (rsa != null) return ("RSA", rsa.KeySize);
        }

        using (var ecdsa = cert.GetECDsaPublicKey())
        {
            if (ecdsa != null) return ("ECDSA", ecdsa.KeySize);
        }

        return (cert.PublicKey.Oid.FriendlyName ?? cert.PublicKey.Oid.Value ?? "Unknown", 0);
    }

    public static string FormatPublicKey(X509Certificate2 cert)
    {
        var (algorithm, size) = DescribeCertificate(cert);
        if (IsPqc(algorithm)) return algorithm;
        return algorithm switch
        {
            "RSA" => $"RSA {size}-bit",
            "ECDSA" => $"ECDSA {size}-bit",
            _ => algorithm
        };
    }

    private static int ParameterSize(string name, int fallback)
    {
        var dash = name.LastIndexOf('-');
        return dash >= 0 && int.TryParse(name[(dash + 1)..], out var size) ? size : fallback;
    }

    private static int SlhSecurityBits(string name)
    {
        if (name.Contains("256", StringComparison.Ordinal)) return 256;
        if (name.Contains("192", StringComparison.Ordinal)) return 192;
        return 128;
    }

    private static int CompositeParameter(string name)
    {
        if (name.StartsWith("MLDSA87", StringComparison.OrdinalIgnoreCase)) return 87;
        if (name.StartsWith("MLDSA65", StringComparison.OrdinalIgnoreCase)) return 65;
        return 44;
    }

    private static PqcAlgorithmInfo A(string family, string id, string label, int keySize, bool canSign) =>
        new(family, id, label, keySize, canSign);
}

public sealed record PqcAlgorithmInfo(string Family, string Id, string Label, int KeySize, bool CanSign);
