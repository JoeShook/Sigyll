<#
.SYNOPSIS
    Runs Sigyll's PKCS #11 tests against a token that is already initialized, through OpenSC.

.DESCRIPTION
    SoftHSM tests initialize a throwaway token and must not be pointed at a hardware token. This script runs only
    Pkcs11HardwareTokenTests, which logs in with an existing user PIN and deletes every key it creates.

    The token's user PIN comes from SIGYLL_TEST_HSM_PIN. It is never written into the repository.

.PARAMETER Replug
    Run only the test that needs the token removed and put back: once it starts, pull the token out, wait a few
    seconds and put it back. The test passes when signing fails while the token is away and works again, with the
    same key, afterwards. It gives up three minutes after it starts.

.EXAMPLE
    $env:SIGYLL_TEST_HSM_PIN = '<user pin>'
    ./tools/opensc/run-hardware-tests.ps1

.EXAMPLE
    ./tools/opensc/run-hardware-tests.ps1 -Replug
#>
param(
    [string]$LibraryPath = "",
    [string]$TokenLabel = "SmartCard-HSM",
    [switch]$Replug
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($env:SIGYLL_TEST_HSM_PIN)) {
    throw "Set SIGYLL_TEST_HSM_PIN to the token's user PIN. This script does not initialize the token."
}

if ([string]::IsNullOrWhiteSpace($LibraryPath)) {
    $candidates = @(
        "$env:ProgramFiles\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
        "$env:LOCALAPPDATA\OpenSC\PFiles64\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
    )
    $LibraryPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if ([string]::IsNullOrWhiteSpace($LibraryPath) -or -not (Test-Path $LibraryPath)) {
    throw "OpenSC's opensc-pkcs11.dll was not found. Install OpenSC, or pass -LibraryPath."
}

$env:SIGYLL_TEST_HSM_LIB = (Resolve-Path $LibraryPath).Path
$env:SIGYLL_TEST_HSM_LABEL = $TokenLabel
$repo = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path

$filter = "FullyQualifiedName~Pkcs11HardwareTokenTests"
if ($Replug) {
    $env:SIGYLL_TEST_HSM_REPLUG = "1"
    $filter = "FullyQualifiedName~Signing_Continues_AfterTheTokenIsRemovedAndPutBack"
    Write-Host "When the test run starts: remove the token, wait a few seconds, and put it back." -ForegroundColor Yellow
}
else {
    $env:SIGYLL_TEST_HSM_REPLUG = $null
}

dotnet test (Join-Path $repo "_tests/Sigyll.Signing.Tests") --filter $filter
exit $LASTEXITCODE
