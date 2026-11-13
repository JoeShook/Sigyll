<#
.SYNOPSIS
    Gets the relay's Windows client library without building it, and prints its path.

.DESCRIPTION
    Downloads sigyll-pkcs11-relay.dll from this repository's GitHub release for the version in the VERSION file
    beside this script (release pkcs11-relay-v<n>), so the library matches the relay server built from the same
    source. The file is kept under %LOCALAPPDATA%\Sigyll\pkcs11-relay\v<n> and downloaded once.

    The download is refused unless its SHA-256 matches the one GitHub records for the release file. When the
    GitHub CLI (gh) is installed, the file's build attestation is checked too: that it was built by this
    repository's workflow.

.PARAMETER Repository
    The GitHub repository to download from, as owner/name.

.PARAMETER Force
    Download again even when the file is already there.

.EXAMPLE
    $dll = ./tools/pkcs11-relay/get-client.ps1
#>
param(
    [string]$Repository = "JoeShook/Sigyll",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$asset = "sigyll-pkcs11-relay-win-x64.dll"

$version = (Get-Content (Join-Path $PSScriptRoot "VERSION") -Raw).Trim()
$tag = "pkcs11-relay-v$version"
$folder = Join-Path $env:LOCALAPPDATA "Sigyll\pkcs11-relay\v$version"
$target = Join-Path $folder "sigyll-pkcs11-relay.dll"

if ((Test-Path $target) -and -not $Force) {
    return $target
}

try {
    $release = Invoke-RestMethod "https://api.github.com/repos/$Repository/releases/tags/$tag" `
        -Headers @{ Accept = "application/vnd.github+json" }
}
catch {
    throw "No release '$tag' in $Repository ($($_.Exception.Message)). It is published when VERSION $version reaches main; until then build the library with run-token-tests.ps1."
}

$file = $release.assets | Where-Object name -eq $asset
if (-not $file) { throw "Release '$tag' has no file named $asset." }
if ($file.digest -notmatch '^sha256:([0-9a-f]{64})$') {
    throw "GitHub did not report a SHA-256 for $asset in release '$tag', so the download cannot be checked."
}
$expected = $Matches[1]

New-Item -ItemType Directory -Force $folder | Out-Null
$download = "$target.download"
Invoke-WebRequest $file.browser_download_url -OutFile $download

$actual = (Get-FileHash $download -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) {
    Remove-Item $download
    throw "The downloaded $asset does not match the release's SHA-256 (expected $expected, got $actual)."
}

if (Get-Command gh -ErrorAction SilentlyContinue) {
    gh attestation verify $download --repo $Repository | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Remove-Item $download
        throw "Could not confirm the build attestation of $asset from $Repository. If gh is not signed in, run 'gh auth login' and try again."
    }
}
else {
    Write-Warning "GitHub CLI (gh) not found: the SHA-256 was checked, the build attestation was not."
}

Move-Item $download $target -Force
return $target
