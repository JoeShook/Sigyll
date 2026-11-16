#!/usr/bin/env bash
# Runs Sigyll's PKCS #11 tests on macOS or Linux against SoftHSM in a Linux container, through the PKCS #11 relay.
#
# Builds the relay client library for this machine, starts the relay server with SoftHSM in a container listening
# on 127.0.0.1, and runs the tests with the client as the PKCS #11 library. The container is removed afterwards.
# See README.md in this folder. On Windows, use run-token-tests.ps1.
#
# Needs Docker and a C compiler for the native build: the Xcode command line tools on macOS, clang and zlib1g-dev
# on Linux.
#
# Usage: ./tools/pkcs11-relay/run-token-tests.sh [dotnet test filter] [more dotnet test arguments]
#   PORT        local port the relay server is published on (default 5696)
#   FAULT_PORT  local port its fault switches are published on, for the reconnect tests (default 5697)
#   SERVER_LOG  file to keep the relay server's output in (not kept by default)
set -euo pipefail

filter="${1:-FullyQualifiedName~Pkcs11}"
[ $# -gt 0 ] && shift
port="${PORT:-5696}"
fault_port="${FAULT_PORT:-5697}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
image="sigyll-pkcs11-relay"
container="sigyll-pkcs11-relay-tests"

case "$(uname -m)" in
    x86_64 | amd64) arch="x64" ;;
    arm64 | aarch64) arch="arm64" ;;
    *) echo "Unsupported processor: $(uname -m)" >&2; exit 1 ;;
esac
case "$(uname -s)" in
    Darwin) rid="osx-$arch"; library="sigyll-pkcs11-relay.dylib" ;;
    Linux) rid="linux-$arch"; library="sigyll-pkcs11-relay.so" ;;
    *) echo "Unsupported system: $(uname -s). On Windows, use run-token-tests.ps1." >&2; exit 1 ;;
esac

client_out="$here/Client/bin/relay-client"
dotnet publish "$here/Client" -c Release -r "$rid" -o "$client_out" -nologo -v q
client="$client_out/$library"
if [ ! -s "$client" ]; then
    echo "The relay client library was not built: $client" >&2
    exit 1
fi

docker build -q -t "$image" "$here" > /dev/null

docker rm -f "$container" > /dev/null 2>&1 || true
stop_server() {
    if [ -n "${SERVER_LOG:-}" ]; then
        docker logs "$container" > "$SERVER_LOG" 2>&1 || true
    fi
    docker rm -f "$container" > /dev/null 2>&1 || true
}
trap stop_server EXIT
docker run -d --name "$container" -p "127.0.0.1:$port:5696" \
    -e PKCS11_RELAY_CONTROL_PORT=5697 -p "127.0.0.1:$fault_port:5697" "$image" > /dev/null

# Docker accepts connections on the published port before the server inside is listening, so wait for the server
# to say it is.
for _ in $(seq 1 100); do
    if docker logs "$container" 2>&1 | grep -q "Relaying PKCS #11 calls"; then break; fi
    sleep 0.2
done

export SIGYLL_TEST_PKCS11_LIB="$client"
export SIGYLL_PKCS11_RELAY="127.0.0.1:$port"
export SIGYLL_TEST_PKCS11_RELAY_FAULTS="127.0.0.1:$fault_port"
dotnet test "$repo/_tests/Sigyll.Signing.Tests" -c Release -nologo --filter "$filter" "$@"
