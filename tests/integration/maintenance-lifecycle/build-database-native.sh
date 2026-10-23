#!/bin/sh
# Isolated component compilation; does not install or modify host packages.
set -eu
src=${1:-/src}
out=${2:-/usr/local/bin}
common="$src/fic-common/fic-core/src"
g++ -std=c++17 -Wall -Wextra -Werror -Wno-error=unused-variable -pthread \
    -I"$src/fic/src" -I"$src/fic-common/fic-core/include" \
    -I"$src/build-env-full-debian12/fic/generated/include" \
    "$src/tests/integration/maintenance-lifecycle/PackageDatabaseDriver.cpp" \
    "$src/fic/src/daemon/PackageDatabaseSnapshot.cpp" \
    "$src/fic/src/daemon/PackageManagerTransactionLock.cpp" "$src/fic/src/daemon/DaemonInstanceLock.cpp" \
    "$src/fic/src/platform/PlatformExecutableResolver.cpp" \
    "$common/fs/RootControlledDirectory.cpp" "$common/process/ProcessExecutor.cpp" \
    "$common/process/ProcessPipeIo.cpp" -o "$out/m1-package-db"
