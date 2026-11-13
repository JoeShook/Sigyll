<#
.SYNOPSIS
    Runs Sigyll's PKCS #11 tests on Windows against SoftHSM in a Linux container, through the PKCS #11 relay.

.DESCRIPTION
    Builds the relay client library (a native Windows DLL), starts the relay server with SoftHSM in a container
    listening on 127.0.0.1, and runs the tests with the DLL as the PKCS #11 library. The container is removed
    afterwards. See README.md in this folder.

    Building the DLL needs the Visual Studio C++ build tools (the "Desktop development with C++" workload, from
    Visual Studio or from Build Tools for Visual Studio). Without them, -UseRelease downloads the released DLL
    instead (get-client.ps1).

.PARAMETER Filter
    dotnet test filter; by default every PKCS #11 test.

.PARAMETER Port
    Local port the relay server is published on.

.PARAMETER UseRelease
    Download the released client DLL for this source's VERSION instead of building it.

.EXAMPLE
    ./tools/pkcs11-relay/run-token-tests.ps1
#>
param(
    [string]$Filter = "FullyQualifiedName~Pkcs11",
    [int]$Port = 5696,
    [switch]$UseRelease
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$image = "sigyll-pkcs11-relay"
$container = "sigyll-pkcs11-relay-tests"

if ($UseRelease) {
    $client = & (Join-Path $PSScriptRoot "get-client.ps1")
}
else {
    # The native build looks for Visual Studio with vswhere, which a plain terminal does not have on its path.
    if (-not (Get-Command vswhere.exe -ErrorAction SilentlyContinue)) {
        $installer = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer"
        if (Test-Path (Join-Path $installer "vswhere.exe")) { $env:PATH = "$installer;$env:PATH" }
    }

    $clientOut = Join-Path $PSScriptRoot "Client/bin/relay-client"
    dotnet publish (Join-Path $PSScriptRoot "Client") -c Release -r win-x64 -o $clientOut -nologo -v q
    if ($LASTEXITCODE -ne 0) { throw "Building the relay client library failed." }
    $client = Join-Path $clientOut "sigyll-pkcs11-relay.dll"
}

docker build -q -t $image $PSScriptRoot | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Building the relay server image failed." }

docker rm -f $container 2>$null | Out-Null
docker run -d --name $container -p "127.0.0.1:${Port}:5696" $image | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Starting the relay server failed." }

try {
    $env:SIGYLL_TEST_PKCS11_LIB = $client
    $env:SIGYLL_PKCS11_RELAY = "127.0.0.1:$Port"
    # Release, so the run does not collide with a Debug build held open by a running AppHost.
    dotnet test (Join-Path $repo "_tests/Sigyll.Signing.Tests") -c Release -nologo --filter $Filter
    $result = $LASTEXITCODE
}
finally {
    docker rm -f $container | Out-Null
}

exit $result
