#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Shouldly;
using Sigyll.UI.Services;

namespace Sigyll.Signing.Tests;

public class TimeDisplayServiceTests
{
    private static readonly DateTime SummerUtc = new(2026, 7, 1, 12, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime WinterUtc = new(2026, 1, 15, 12, 0, 0, DateTimeKind.Utc);

    private static TimeDisplayService Local(string zone)
    {
        var svc = new TimeDisplayService();
        svc.SetLocalTimeZone(zone);
        svc.SetUseLocalTime(true);
        return svc;
    }

    [Fact]
    public void Utc_mode_shows_a_utc_time_unchanged()
    {
        var svc = new TimeDisplayService();

        svc.Format(SummerUtc).ShouldBe("2026-07-01 12:00:00 UTC");
        svc.FormatMedium(SummerUtc).ShouldBe("2026-07-01 12:00");
        svc.FormatShort(SummerUtc).ShouldBe("2026-07-01");
        svc.Label.ShouldBe("UTC");
    }

    [Fact]
    public void Utc_mode_converts_a_local_kind_to_utc()
    {
        // X509Certificate2.NotBefore/NotAfter come back in the server's zone.
        var local = SummerUtc.ToLocalTime();
        local.Kind.ShouldBe(DateTimeKind.Local);

        new TimeDisplayService().Format(local).ShouldBe("2026-07-01 12:00:00 UTC");
    }

    [Fact]
    public void Unspecified_kind_is_taken_as_utc()
    {
        var unspecified = DateTime.SpecifyKind(SummerUtc, DateTimeKind.Unspecified);

        new TimeDisplayService().Format(unspecified).ShouldBe("2026-07-01 12:00:00 UTC");
        Local("Asia/Tokyo").Format(unspecified).ShouldBe("2026-07-01 21:00:00 Local");
    }

    [Fact]
    public void Local_mode_uses_the_browser_zone_not_the_server_zone()
    {
        var svc = Local("Asia/Tokyo");

        svc.Format(SummerUtc).ShouldBe("2026-07-01 21:00:00 Local");
        svc.FormatMedium(SummerUtc).ShouldBe("2026-07-01 21:00");
        svc.Label.ShouldBe("Local");
    }

    [Fact]
    public void Local_mode_follows_daylight_saving_time()
    {
        var svc = Local("America/Los_Angeles");

        svc.FormatMedium(SummerUtc).ShouldBe("2026-07-01 05:00"); // PDT, UTC-7
        svc.FormatMedium(WinterUtc).ShouldBe("2026-01-15 04:00"); // PST, UTC-8
    }

    [Fact]
    public void Local_mode_converts_a_local_kind_through_utc()
    {
        var svc = Local("America/Los_Angeles");

        svc.FormatMedium(SummerUtc.ToLocalTime()).ShouldBe("2026-07-01 05:00");
    }

    [Fact]
    public void Local_mode_shifts_the_date_when_the_zone_crosses_midnight()
    {
        var lateUtc = new DateTime(2026, 3, 1, 20, 0, 0, DateTimeKind.Utc);

        Local("Asia/Tokyo").FormatShort(lateUtc).ShouldBe("2026-03-02");
        new TimeDisplayService().FormatShort(lateUtc).ShouldBe("2026-03-01");
    }

    [Fact]
    public void DateTimeOffset_is_shown_by_its_instant()
    {
        var dto = new DateTimeOffset(2026, 7, 1, 8, 0, 0, TimeSpan.FromHours(-4)); // 12:00 UTC

        new TimeDisplayService().Format(dto, "HH:mm:ss").ShouldBe("12:00:00 UTC");
        Local("Asia/Tokyo").Format(dto, "HH:mm:ss").ShouldBe("21:00:00 Local");
    }

    [Theory]
    [InlineData("Not/AZone")]
    [InlineData("")]
    [InlineData(null)]
    public void Bad_zone_id_falls_back_to_utc(string? zone)
    {
        var svc = Local("Asia/Tokyo");
        svc.SetLocalTimeZone(zone);

        svc.LocalTimeZone.ShouldBe(TimeZoneInfo.Utc);
        svc.Format(SummerUtc).ShouldBe("2026-07-01 12:00:00 Local");
    }

    [Fact]
    public void Changing_the_zone_notifies_only_when_local_time_is_shown()
    {
        var svc = new TimeDisplayService();
        var changes = 0;
        svc.OnChanged += () => changes++;

        svc.SetLocalTimeZone("Asia/Tokyo");
        changes.ShouldBe(0);

        svc.SetUseLocalTime(true);
        svc.SetLocalTimeZone("America/Los_Angeles");
        changes.ShouldBe(2);

        svc.SetLocalTimeZone("America/Los_Angeles");
        changes.ShouldBe(2);
    }

    [Fact]
    public void Far_future_placeholder_does_not_overflow()
    {
        // A CRL without a NextUpdate is stored as DateTime.MaxValue.
        var max = DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc);

        Should.NotThrow(() => Local("Asia/Tokyo").FormatShort(max));
        Should.NotThrow(() => Local("America/Los_Angeles").FormatShort(DateTime.MinValue));
    }
}
