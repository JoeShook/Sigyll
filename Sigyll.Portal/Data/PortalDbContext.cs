#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Sigyll.Portal.Data.Entities;

namespace Sigyll.Portal.Data;

/// <summary>
/// EF Core context for the certificate request portal: ASP.NET Core Identity (users, roles,
/// passkeys) plus the portal's own request/RA-workflow entities. Lives in its own PostgreSQL
/// schema <c>portal</c>, fully separate from the CA core's <c>sigil</c> schema (true RA/CA split).
/// </summary>
public class PortalDbContext(DbContextOptions<PortalDbContext> options) : IdentityDbContext<PortalUser>(options)
{
    public const string Schema = "portal";

    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<OrganizationMembership> OrganizationMemberships => Set<OrganizationMembership>();
    public DbSet<CertificateRequest> CertificateRequests => Set<CertificateRequest>();
    public DbSet<RequestEvent> RequestEvents => Set<RequestEvent>();
    public DbSet<DomainValidationChallenge> DomainValidationChallenges => Set<DomainValidationChallenge>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        builder.HasDefaultSchema(Schema);
        base.OnModelCreating(builder);

        builder.Entity<OrganizationMembership>(e =>
        {
            e.HasOne(m => m.Organization)
                .WithMany(o => o.Memberships)
                .HasForeignKey(m => m.OrganizationId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(m => new { m.OrganizationId, m.UserId }).IsUnique();
            e.HasIndex(m => m.UserId);
        });

        builder.Entity<CertificateRequest>(e =>
        {
            e.HasIndex(r => r.RequesterId);
            e.HasIndex(r => r.Status);
        });

        builder.Entity<RequestEvent>(e =>
        {
            e.HasOne(ev => ev.Request)
                .WithMany(r => r.Events)
                .HasForeignKey(ev => ev.RequestId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(ev => ev.RequestId);
        });

        builder.Entity<DomainValidationChallenge>(e =>
        {
            e.HasOne(c => c.Request)
                .WithMany(r => r.Challenges)
                .HasForeignKey(c => c.RequestId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(c => c.RequestId);
            e.HasIndex(c => c.Token);
        });
    }
}
