#!/bin/sh
# Runs inside a .NET SDK container (see run-token-tests.ps1): installs SoftHSM from Ubuntu, points it at a token
# store under /tmp, and runs the PKCS #11 tests against it. The repository is mounted read-only and copied first,
# so no Linux build output lands in the working tree. Each test run creates its own throwaway token.
set -eu
filter="${1:-FullyQualifiedName~Pkcs11}"

apt-get update -qq >/dev/null
apt-get install -y -qq softhsm2 >/dev/null 2>&1

mkdir -p /tmp/softhsm/tokens
printf 'directories.tokendir = /tmp/softhsm/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' \
  > /tmp/softhsm/softhsm2.conf
export SOFTHSM2_CONF=/tmp/softhsm/softhsm2.conf
export SIGYLL_TEST_PKCS11_LIB=/usr/lib/softhsm/libsofthsm2.so

cp -r /repo /tmp/src
cd /tmp/src
find . -type d \( -name bin -o -name obj \) -prune -exec rm -rf {} +

echo "SoftHSM $(dpkg-query -W -f '${Version}' softhsm2); running tests matching: $filter"
dotnet test _tests/Sigyll.Signing.Tests --artifacts-path /tmp/out -nologo \
  --filter "$filter" --logger "console;verbosity=normal"
