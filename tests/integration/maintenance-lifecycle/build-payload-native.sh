#!/bin/sh
# Independent read-only manifest/generator probe; no FIC installation.
set -eu
src=${1:-/src}
out=${2:-/usr/local/bin}
common="$src/fic-common/fic-core/src"
g++ -std=c++17 -Wall -Wextra -Werror -Wno-error=unused-variable -pthread \
    -I"$src/fic/src" -I"$src/fic-common/fic-core/include" \
    "$src/tests/fic/daemon/PackagePayloadManifestTests.cpp" \
    "$src/fic/src/daemon/PackagePayloadManifest.cpp" \
    "$common/fs/AtomicFileWriter.cpp" "$common/fs/SecureStateFile.cpp" \
    "$common/fs/RootControlledDirectory.cpp" "$common/integrity/ContentDigest.cpp" \
    "$common/process/ProcessExecutor.cpp" "$common/process/ProcessPipeIo.cpp" \
    -lcrypto -o "$out/m1-payload-tests"
