#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.UI.Services;

/// <summary>
/// Formats instants for display in UTC or in the operator's own time zone.
/// "Local" means the browser's zone (reported by <c>Intl.DateTimeFormat</c> and
/// set through <see cref="SetLocalTimeZone"/>), never the server's: the server may
/// run in a UTC container or in another zone than the operator.
/// </summary>
public class TimeDisplayService
{
    public bool UseLocalTime { get; private set; }

    /// <summary>The operator's time zone; UTC until the browser reports one.</summary>
    public TimeZoneInfo LocalTimeZone { get; private set; } = TimeZoneInfo.Utc;

    public event Action? OnChanged;

    public void SetUseLocalTime(bool value)
    {
        if (UseLocalTime == value) return;
        UseLocalTime = value;
        OnChanged?.Invoke();
    }

    /// <summary>
    /// Sets the operator's zone from an IANA id such as <c>America/Los_Angeles</c>.
    /// An empty or unknown id falls back to UTC.
    /// </summary>
    public void SetLocalTimeZone(string? timeZoneId)
    {
        var zone = ResolveTimeZone(timeZoneId);
        if (zone.Id == LocalTimeZone.Id) return;
        LocalTimeZone = zone;
        if (UseLocalTime) OnChanged?.Invoke();
    }

    public static TimeZoneInfo ResolveTimeZone(string? timeZoneId)
    {
        if (string.IsNullOrWhiteSpace(timeZoneId)) return TimeZoneInfo.Utc;
        try
        {
            return TimeZoneInfo.FindSystemTimeZoneById(timeZoneId.Trim());
        }
        catch (Exception ex) when (ex is TimeZoneNotFoundException or InvalidTimeZoneException)
        {
            return TimeZoneInfo.Utc;
        }
    }

    /// <summary>
    /// Converts an instant to the selected display zone. A Local kind (for example
    /// <c>X509Certificate2.NotBefore</c>) is converted to UTC first; an Unspecified
    /// kind is taken as UTC, because every stored timestamp is UTC.
    /// </summary>
    public DateTime ToDisplayTime(DateTime dt)
    {
        var utc = dt.Kind switch
        {
            DateTimeKind.Local => dt.ToUniversalTime(),
            DateTimeKind.Utc => dt,
            _ => DateTime.SpecifyKind(dt, DateTimeKind.Utc)
        };
        return UseLocalTime ? TimeZoneInfo.ConvertTimeFromUtc(utc, LocalTimeZone) : utc;
    }

    public DateTime ToDisplayTime(DateTimeOffset dto) => ToDisplayTime(dto.UtcDateTime);

    public string Format(DateTime dt, string format = "yyyy-MM-dd HH:mm:ss") =>
        ToDisplayTime(dt).ToString(format) + " " + Label;

    public string Format(DateTimeOffset dto, string format = "yyyy-MM-dd HH:mm:ss") =>
        Format(dto.UtcDateTime, format);

    public string FormatShort(DateTime dt) => ToDisplayTime(dt).ToString("yyyy-MM-dd");

    public string FormatShort(DateTimeOffset dto) => FormatShort(dto.UtcDateTime);

    public string FormatMedium(DateTime dt) => ToDisplayTime(dt).ToString("yyyy-MM-dd HH:mm");

    public string FormatMedium(DateTimeOffset dto) => FormatMedium(dto.UtcDateTime);

    public string Label => UseLocalTime ? "Local" : "UTC";
}
