<#
.SYNOPSIS
    Runs Sigyll's PKCS #11 tests against a token that is already initialized, through OpenSC.

.DESCRIPTION
    SoftHSM tests initialize a throwaway token and must not be pointed at a hardware token. This script runs only
    Pkcs11HardwareTokenTests, which logs in with an existing user PIN and deletes every key it creates.

    The token's user PIN comes from SIGYLL_TEST_HSM_PIN. It is never written into the repository.

.EXAMPLE
    $env:SIGYLL_TEST_HSM_PIN = '<user pin>'
    ./tools/opensc/run-hardware-tests.ps1
#>
param(
    [string]$LibraryPath = "",
    [string]$TokenLabel = "SmartCard-HSM"
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

dotnet test (Join-Path $repo "_tests/Sigyll.Signing.Tests") --filter "FullyQualifiedName~Pkcs11HardwareTokenTests"
exit $LASTEXITCODE
