#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Net;
using System.Text.RegularExpressions;

namespace Sigyll.Tests;

/// <summary>Where a request ended up, after redirects, and what it showed.</summary>
public sealed record Page(HttpStatusCode Status, Uri Url, string Html)
{
    public string PathAndQuery => Url.PathAndQuery;
}

/// <summary>What a browser does with a server-rendered page: follow links, fill in and submit its forms.</summary>
public static partial class Browser
{
    /// <summary>
    /// Fills in and submits the form on <paramref name="page"/> named <paramref name="formName"/>, as a browser does:
    /// its hidden fields (antiforgery token, form name) plus the given ones. Returns the page the browser ends on.
    /// </summary>
    public static async Task<Page> SubmitAsync(
        HttpClient browser, string page, string formName, IReadOnlyDictionary<string, string> fields)
    {
        var html = await browser.GetStringAsync(page);
        var form = Forms().Matches(html).FirstOrDefault(f => HiddenFields(f.Value).GetValueOrDefault("_handler") == formName)
            ?? throw new InvalidOperationException($"No form '{formName}' on {page}.");
        var values = HiddenFields(form.Value);
        foreach (var (name, value) in fields)
            values[name] = value;
        return await PostAsync(browser, page, values);
    }

    /// <summary>Posts to <paramref name="url"/> with the antiforgery token of <paramref name="tokenPage"/>.</summary>
    public static async Task<Page> PostWithTokenAsync(
        HttpClient browser, string tokenPage, string url, IReadOnlyDictionary<string, string> fields)
    {
        var html = await browser.GetStringAsync(tokenPage);
        var values = new Dictionary<string, string>(fields)
        {
            ["__RequestVerificationToken"] = HiddenFields(html)["__RequestVerificationToken"],
        };
        return await PostAsync(browser, url, values);
    }

    public static async Task<Page> GetAsync(HttpClient browser, string url)
    {
        var response = await browser.GetAsync(url);
        return new Page(response.StatusCode, response.RequestMessage!.RequestUri!, await response.Content.ReadAsStringAsync());
    }

    private static async Task<Page> PostAsync(HttpClient browser, string url, Dictionary<string, string> values)
    {
        var response = await browser.PostAsync(url, new FormUrlEncodedContent(values));
        return new Page(response.StatusCode, response.RequestMessage!.RequestUri!, await response.Content.ReadAsStringAsync());
    }

    private static Dictionary<string, string> HiddenFields(string html)
    {
        var fields = new Dictionary<string, string>();
        foreach (Match input in Inputs().Matches(html))
        {
            var tag = input.Value;
            if (!tag.Contains("type=\"hidden\"", StringComparison.OrdinalIgnoreCase))
                continue;
            if (Name().Match(tag) is { Success: true } name)
                fields.TryAdd(WebUtility.HtmlDecode(name.Groups[1].Value),
                    WebUtility.HtmlDecode(Value().Match(tag) is { Success: true } v ? v.Groups[1].Value : ""));
        }
        return fields;
    }

    [GeneratedRegex("<form\\b.*?</form>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex Forms();

    [GeneratedRegex("<input\\b[^>]*>", RegexOptions.IgnoreCase)]
    private static partial Regex Inputs();

    [GeneratedRegex("\\bname=\"([^\"]*)\"")]
    private static partial Regex Name();

    [GeneratedRegex("\\bvalue=\"([^\"]*)\"")]
    private static partial Regex Value();
}
