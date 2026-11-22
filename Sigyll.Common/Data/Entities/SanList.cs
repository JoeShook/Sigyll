#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Common.Data.Entities;

public class SanList
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }

    /// <summary>
    /// Semicolon-delimited SAN entries: "URI:urn:oid:...#T-TRTMNT;URI:urn:oid:...#T-TREAT;DNS:example.com".
    /// Type tokens are URI, DNS, Email, IP and NPI (a 10-digit NPI, e.g. "NPI:1234567893").
    /// </summary>
    public string Items { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<CertificateProfile> Profiles { get; set; } = new List<CertificateProfile>();
}
