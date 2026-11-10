#:property PublishAot=false
// Writes THIRD-PARTY-NOTICES.txt for a published Sigyll application: every NuGet package the application ships
// with, its licence and copyright, the notice files those packages ask redistributors to pass on (Apache-2.0
// section 4(d) NOTICE files, Microsoft's third-party notices), and the licence texts.
//
// The list comes from the published <app>.deps.json, so it is exactly what ships, at the versions that ship; the
// texts come from the packages themselves in the NuGet package folder. A package that ships no licence file gets
// the standard text for its SPDX identifier from licences/<id>.txt. The run fails when a package's licence text
// can't be found, so a new dependency can't ship without one.
//
// Run from the repository root, after `dotnet publish`:
//   dotnet run tools/third-party-notices/ThirdPartyNotices.cs -- <output file> <app.deps.json | extra.txt>...
// A .txt input is appended as written, for components that aren't NuGet packages (see vendored/).
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

if (args.Length < 2)
{
    Console.Error.WriteLine("Usage: ThirdPartyNotices.cs <output file> <app.deps.json | extra.txt>...");
    return 2;
}

var standardTexts = Path.Combine("tools", "third-party-notices", "licences");
if (!Directory.Exists(standardTexts))
{
    Console.Error.WriteLine($"Run from the repository root: {standardTexts} was not found.");
    return 2;
}

var packageFolder = Environment.GetEnvironmentVariable("NUGET_PACKAGES") is { Length: > 0 } configured
    ? configured
    : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages");

// The packages each application ships, by "Id/Version", and any extra texts to append.
var shipped = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
var extras = new List<string>();
foreach (var input in args.Skip(1))
{
    if (!input.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
    {
        extras.Add(TextSet.Normalise(ReadText(input)));
        continue;
    }

    using var deps = JsonDocument.Parse(File.ReadAllBytes(input));
    foreach (var library in deps.RootElement.GetProperty("libraries").EnumerateObject())
    {
        if (library.Value.GetProperty("type").GetString() != "package") continue;
        var path = library.Value.TryGetProperty("path", out var p) ? p.GetString() : null;
        shipped[library.Name] = path ?? library.Name.ToLowerInvariant();
    }
}

var problems = new List<string>();
var packages = new List<Package>();
var licenceTexts = new TextSet();
var noticeTexts = new TextSet();

foreach (var (key, relativePath) in shipped)
{
    var folder = Path.Combine(packageFolder, relativePath.Replace('/', Path.DirectorySeparatorChar));
    var nuspecPath = Directory.Exists(folder) ? Directory.EnumerateFiles(folder, "*.nuspec").FirstOrDefault() : null;
    if (nuspecPath is null)
    {
        problems.Add($"{key}: not in the NuGet package folder ({folder}); restore before running");
        continue;
    }

    var metadata = XDocument.Load(nuspecPath).Root!.Elements().First(e => e.Name.LocalName == "metadata");
    string? Field(string name) => metadata.Elements().FirstOrDefault(e => e.Name.LocalName == name)?.Value.Trim();

    var licence = metadata.Elements().FirstOrDefault(e => e.Name.LocalName == "license");
    var licenceIsFile = licence?.Attribute("type")?.Value == "file";
    var expression = licenceIsFile ? null : licence?.Value.Trim();
    var files = Directory.EnumerateFiles(folder).OrderBy(f => f, StringComparer.Ordinal).ToList();

    // Licence text: the file the package names, else a licence file at its root, else the package's own or the
    // standard text kept in licences/.
    var licenceFile = licenceIsFile
        ? Path.Combine(folder, licence!.Value.Trim().Replace('/', Path.DirectorySeparatorChar))
        : files.FirstOrDefault(f => Regex.IsMatch(Path.GetFileName(f), @"^(licen[sc]e|copying)(\.(txt|md))?$", RegexOptions.IgnoreCase));
    var id = Field("id") ?? key.Split('/')[0];
    licenceFile ??= new[] { id, expression }
        .Where(name => !string.IsNullOrEmpty(name))
        .Select(name => Path.Combine(standardTexts, name + ".txt"))
        .FirstOrDefault(File.Exists);

    if (licenceFile is null || !File.Exists(licenceFile))
    {
        problems.Add($"{key}: no licence text found (declared: {expression ?? licence?.Value ?? Field("licenseUrl") ?? "nothing"}); " +
                     $"add {standardTexts.Replace('\\', '/')}/<SPDX id or package id>.txt");
        continue;
    }

    // Notice files a redistributor has to pass on. Rich-text copies are skipped: the licences they repeat are
    // already listed for the package.
    var notices = files
        .Where(f => Regex.IsMatch(Path.GetFileName(f), @"^(notice|third-?party-?notices)(\.(txt|md))?$", RegexOptions.IgnoreCase))
        .Select(f => noticeTexts.Add(ReadText(f)))
        .Distinct()
        .ToList();

    var package = new Package(
        id,
        Field("version") ?? key.Split('/')[1],
        expression,
        Field("copyright") is { Length: > 0 } copyright ? copyright : $"Copyright (c) {Field("authors") ?? id}",
        Field("projectUrl") ?? metadata.Elements().FirstOrDefault(e => e.Name.LocalName == "repository")?.Attribute("url")?.Value,
        licenceTexts.Add(ReadText(licenceFile)),
        notices);
    packages.Add(package);
}

packages.Sort((a, b) => StringComparer.OrdinalIgnoreCase.Compare(a.Id, b.Id) is not 0 and var byId
    ? byId
    : StringComparer.OrdinalIgnoreCase.Compare(a.Version, b.Version));

if (problems.Count > 0)
{
    foreach (var problem in problems) Console.Error.WriteLine($"::error::{problem}");
    Console.Error.WriteLine($"{problems.Count} package(s) could not be given a notice; THIRD-PARTY-NOTICES was not written.");
    return 1;
}

const string rule = "================================================================================";
var text = new StringBuilder();
text.Append($"""
    THIRD-PARTY NOTICES

    Sigyll is licensed under the MIT License (see LICENSE). It includes the third-party
    software listed below, each under its own licence. This file is generated when
    Sigyll is built, from the packages the application ships with.

    The .NET runtime, where it is distributed with Sigyll (for example in a container
    image), carries its own licence and notices alongside it.

    Contents
      1. Components     - each package, its licence and its copyright holder
      2. Notices        - notice files those packages ask to be passed on
      3. Licence texts  - the full text of each licence


    {rule}
    1. COMPONENTS
    {rule}

    """.ReplaceLineEndings("\n"));

foreach (var package in packages)
{
    text.Append($"\n{package.Id} {package.Version}\n");
    text.Append(package.Licence is null
        ? $"  Licence:   licence text {package.LicenceText}\n"
        : $"  Licence:   {package.Licence} (licence text {package.LicenceText})\n");
    text.Append($"  Copyright: {package.Copyright}\n");
    if (package.Url is not null) text.Append($"  Source:    {package.Url}\n");
    if (package.Notices.Count > 0) text.Append($"  Notices:   {string.Join(", ", package.Notices.Select(n => $"notice {n}"))}\n");
}

foreach (var extra in extras) text.Append('\n').Append(extra).Append('\n');

text.Append($"\n\n{rule}\n2. NOTICES\n{rule}\n");
WriteTexts(noticeTexts, "Notice", p => p.Notices);

text.Append($"\n\n{rule}\n3. LICENCE TEXTS\n{rule}\n");
WriteTexts(licenceTexts, "Licence text", p => [p.LicenceText]);

Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(args[0]))!);
File.WriteAllText(args[0], text.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
Console.WriteLine($"{args[0]}: {packages.Count} packages, {noticeTexts.Count} notices, {licenceTexts.Count} licence texts.");
return 0;

void WriteTexts(TextSet texts, string label, Func<Package, IEnumerable<int>> numbersOf)
{
    for (var number = 1; number <= texts.Count; number++)
    {
        var users = packages.Where(p => numbersOf(p).Contains(number)).Select(p => $"{p.Id} {p.Version}");
        text.Append($"\n{label} {number}\nApplies to: {string.Join(", ", users)}\n");
        text.Append("--------------------------------------------------------------------------------\n");
        text.Append(texts[number]).Append('\n');
    }
}

// Packages are mostly UTF-8, but a few older licence files are Windows-1252/Latin-1.
static string ReadText(string path)
{
    var bytes = File.ReadAllBytes(path);
    try
    {
        return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes).TrimStart('﻿');
    }
    catch (DecoderFallbackException)
    {
        return Encoding.Latin1.GetString(bytes);
    }
}

record Package(string Id, string Version, string? Licence, string Copyright, string? Url, int LicenceText, List<int> Notices);

/// <summary>Distinct texts, numbered from 1 in the order first seen, so a text shared by many packages appears once.</summary>
class TextSet
{
    private readonly Dictionary<string, int> _numbers = new();
    private readonly List<string> _texts = [];

    public int Count => _texts.Count;
    public string this[int number] => _texts[number - 1];

    /// <summary>LF line endings, no trailing spaces, no blank lines at either end.</summary>
    public static string Normalise(string value) =>
        string.Join('\n', value.ReplaceLineEndings("\n").Split('\n').Select(line => line.TrimEnd())).Trim('\n');

    public int Add(string value)
    {
        var text = Normalise(value);
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
        if (_numbers.TryGetValue(hash, out var number)) return number;
        _texts.Add(text);
        return _numbers[hash] = _texts.Count;
    }
}
