#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using Sigyll.Contracts;

namespace Sigyll.Portal.Services;

/// <summary>
/// Parses a caller-supplied PKCS#10 CSR for display/prefill in the request wizard — subject DN and
/// any DNS SANs. The portal only reads the CSR (public material); it never handles the private key.
/// </summary>
public static class CsrParser
{
    public record ParsedCsr(string SubjectDn, List<ApiSanEntry> Sans);

    public static ParsedCsr Parse(string csrPem)
    {
        var req = CertificateRequest.LoadSigningRequestPem(
            csrPem,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        var sans = new List<ApiSanEntry>();
        foreach (var ext in req.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>())
        {
            foreach (var dns in ext.EnumerateDnsNames())
                sans.Add(new ApiSanEntry { Type = "Dns", Value = dns });
            foreach (var ip in ext.EnumerateIPAddresses())
                sans.Add(new ApiSanEntry { Type = "IpAddress", Value = ip.ToString() });
        }

        return new ParsedCsr(req.SubjectName.Name, sans);
    }
}
