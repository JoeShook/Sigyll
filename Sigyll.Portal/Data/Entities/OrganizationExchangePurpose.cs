#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Portal.Data.Entities;

/// <summary>
/// An exchange purpose (e.g. <c>T-TRTMNT</c>) a subscriber organization is authorized to carry in its certificates'
/// SANs, and who recorded that authorization. Withdrawing it removes the row; the audit trail keeps the history.
/// </summary>
public class OrganizationExchangePurpose
{
    public int Id { get; set; }

    public int OrganizationId { get; set; }
    public Organization Organization { get; set; } = null!;

    /// <summary>Exchange purpose code, upper-case (see <c>ExchangePurposeSan</c>).</summary>
    public string Code { get; set; } = string.Empty;

    /// <summary>The RA or portal admin who recorded the authorization.</summary>
    public string ApprovedBy { get; set; } = string.Empty;

    public DateTime ApprovedAt { get; set; } = DateTime.UtcNow;
}
