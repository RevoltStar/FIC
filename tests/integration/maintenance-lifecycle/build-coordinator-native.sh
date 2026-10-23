#!/bin/sh
# Build only the preparation probe for the disposable native systemd fixture.
set -eu
src=${1:-/src}
out=${2:-/usr/local/bin}
common="$src/fic-common/fic-core/src"
inc="$src/build-env-full-debian12/fic/generated/include"
set -- -std=c++17 -Wall -Wextra -Werror -Wno-error=unused-variable -pthread \
    -I"$src/fic/src" -I"$src/fic-common/fic-core/include" -I"$inc"
g++ "$@" "$src/tests/integration/maintenance-lifecycle/CoordinatorDriver.cpp" \
    "$src/fic/src/daemon/PackageLifecycleCoordinator.cpp" \
    "$src/fic/src/daemon/PackageLifecycleState.cpp" \
    "$src/fic/src/daemon/PackageWritersQuiescence.cpp" \
    "$src/fic/src/daemon/PackageUnitMasks.cpp" \
    "$src/fic/src/daemon/PackageWriterProcesses.cpp" \
    "$src/fic/src/daemon/PackageWriterInventory.cpp" \
    "$src/fic/src/daemon/StoppedWritersProof.cpp" \
    "$src/fic/src/daemon/DaemonInstanceLock.cpp" \
    "$src/fic/src/platform/PlatformExecutableResolver.cpp" \
    "$common/fs/AtomicFileWriter.cpp" "$common/fs/SecureStateFile.cpp" \
    "$common/fs/RootControlledDirectory.cpp" "$common/fs/FileStats.cpp" \
    "$common/integrity/ContentDigest.cpp" \
    "$common/process/ExclusivePidLock.cpp" \
    "$common/process/ProcessExecutor.cpp" "$common/process/ProcessPipeIo.cpp" \
    -lcrypto -o "$out/m1-coordinator"
