#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigyll.Common.Services.Publishing;

/// <summary>A publishing path that would write outside where Sigyll may write.</summary>
public sealed class PublishingPathException(string message) : Exception(message);

/// <summary>
/// Where Sigyll may write published certificates and CRLs. A trust domain's publishing folder is set by an Admin in
/// the database; the folders it may point into are set by the deployment (<c>Publishing:AllowedRoots</c>), so a
/// database change alone can't make Sigyll write anywhere else. File names are a CA's name, so they must be plain
/// names that stay inside the folder.
/// </summary>
public sealed class PublishingPathPolicy
{
    /// <summary>No folder restriction (Development without configured roots, and tests); names are still checked.</summary>
    public static readonly PublishingPathPolicy Unrestricted = new([], requireAllowedRoot: false);

    private readonly string[] _roots;
    private readonly bool _requireAllowedRoot;

    /// <param name="allowedRoots">Folders publishing may write into; relative ones resolve against the current directory.</param>
    /// <param name="requireAllowedRoot">When true, an empty <paramref name="allowedRoots"/> refuses every folder.</param>
    public PublishingPathPolicy(IEnumerable<string> allowedRoots, bool requireAllowedRoot)
    {
        _roots = allowedRoots.Where(r => !string.IsNullOrWhiteSpace(r)).Select(Path.GetFullPath).ToArray();
        _requireAllowedRoot = requireAllowedRoot;
    }

    public IReadOnlyList<string> AllowedRoots => _roots;

    /// <summary>The full path of <paramref name="fileName"/> in <paramref name="folder"/> under the publishing base.</summary>
    /// <exception cref="PublishingPathException">The name isn't a plain file name, or the path is outside the allowed folders.</exception>
    public string Resolve(string basePath, string folder, string fileName)
    {
        if (!IsPlainFileName(fileName))
            throw new PublishingPathException(
                $"'{fileName}' can't be published: a published file name can't contain path characters or '..'.");

        var baseFull = Path.GetFullPath(basePath);
        if ((_roots.Length > 0 || _requireAllowedRoot) && !_roots.Any(root => IsUnder(baseFull, root)))
            throw new PublishingPathException(
                $"Publishing folder '{baseFull}' is outside Publishing:AllowedRoots.");

        var full = Path.GetFullPath(Path.Combine(baseFull, folder, fileName));
        if (!IsUnder(full, baseFull))
            throw new PublishingPathException($"'{full}' is outside the publishing folder '{baseFull}'.");
        return full;
    }

    private static bool IsPlainFileName(string name) =>
        !string.IsNullOrWhiteSpace(name)
        && name.Trim() is not ("." or "..")
        && !name.Contains("..")
        && name.IndexOfAny(['/', '\\', ':']) < 0
        && name.IndexOfAny(Path.GetInvalidFileNameChars()) < 0;

    private static bool IsUnder(string path, string root)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var rootWithSeparator = Path.EndsInDirectorySeparator(root) ? root : root + Path.DirectorySeparatorChar;
        return path.Equals(root.TrimEnd(Path.DirectorySeparatorChar), comparison)
            || path.StartsWith(rootWithSeparator, comparison);
    }
}
