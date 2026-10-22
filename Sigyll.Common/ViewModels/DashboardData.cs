#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Common.ViewModels;

public class DashboardData
{
    public int TrustDomainCount { get; set; }
    public int CaCertCount { get; set; }
    public int IssuedCertCount { get; set; }
    public int ProfileCount { get; set; }
    public int RevokedCertCount { get; set; }
    public List<TrustDomainSummary> TrustDomainSummaries { get; set; } = new();
    public List<CertRow> ExpiringCerts { get; set; } = new();
    public List<CertRow> ExpiredCerts { get; set; } = new();

    /// <summary>
    /// Expired or expiring certificates whose auto-renew is off: left to expire on purpose (a
    /// negative-test certificate, say), so they are reported apart and raise no warning.
    /// </summary>
    public List<CertRow> NotRenewingCerts { get; set; } = new();
    public List<CrlRow> OverdueCrls { get; set; } = new();
}

public class TrustDomainSummary
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public int CaCount { get; set; }
    public int IssuedCount { get; set; }
    public int ExpiredCaCount { get; set; }
    public int ExpiredIssuedCount { get; set; }
    public int ExpiringCaCount { get; set; }
    public int ExpiringIssuedCount { get; set; }
    public int OverdueCrlCount { get; set; }

    /// <summary>Expired or expiring certificates with auto-renew off; informational only.</summary>
    public int NotRenewingCount { get; set; }
    public int TotalCerts => CaCount + IssuedCount;
    public int TotalExpired => ExpiredCaCount + ExpiredIssuedCount;
    public int TotalExpiring => ExpiringCaCount + ExpiringIssuedCount;
    public bool IsHealthy => TotalExpired == 0 && TotalExpiring == 0 && OverdueCrlCount == 0;
}

public class CertRow
{
    public string Name { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string Thumbprint { get; set; } = string.Empty;
    public DateTime NotAfter { get; set; }
    public string TrustDomainName { get; set; } = string.Empty;
    public int TrustDomainId { get; set; }
    public string CertType { get; set; } = string.Empty;
    public int DaysRemaining { get; set; }
    public bool IsExpired { get; set; }
    public bool AutoRenew { get; set; } = true;
}

public class CrlRow
{
    public long CrlNumber { get; set; }
    public string CaName { get; set; } = string.Empty;
    public string CaThumbprint { get; set; } = string.Empty;
    public string TrustDomainName { get; set; } = string.Empty;
    public int TrustDomainId { get; set; }
    public DateTime NextUpdate { get; set; }
    public int DaysOverdue { get; set; }
}
