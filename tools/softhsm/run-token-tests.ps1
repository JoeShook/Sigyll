<#
.SYNOPSIS
    Runs Sigyll's PKCS #11 tests against SoftHSM in a Linux container, from Windows or anywhere Docker runs.

.DESCRIPTION
    SoftHSM has no maintained Windows build, and Sigyll runs in a Linux container, so the token tests run in the
    same .NET SDK image the Sigyll Dockerfile builds with (its pinned digest), with SoftHSM from Ubuntu. Nothing is
    installed on this machine and no build output is written to the working tree.

.PARAMETER Filter
    dotnet test filter; by default every PKCS #11 test.

.EXAMPLE
    ./tools/softhsm/run-token-tests.ps1
.EXAMPLE
    ./tools/softhsm/run-token-tests.ps1 -Filter "FullyQualifiedName~Pkcs11SoftHsmTests.TokenCa"
#>
param([string]$Filter = "FullyQualifiedName~Pkcs11")

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path

# Use the SDK image the Sigyll Dockerfile pins, so the tests build with the same toolchain as the container.
$sdk = (Select-String -Path (Join-Path $repo "Sigyll/Dockerfile") -Pattern '^FROM\s+(mcr\.microsoft\.com/dotnet/sdk\S+)').Matches |
    Select-Object -First 1 | ForEach-Object { $_.Groups[1].Value }
if (-not $sdk) { throw "Could not find the .NET SDK image in Sigyll/Dockerfile." }

docker run --rm -v "${repo}:/repo:ro" -v "${PSScriptRoot}:/tool:ro" $sdk sh /tool/run-token-tests.sh $Filter
exit $LASTEXITCODE
