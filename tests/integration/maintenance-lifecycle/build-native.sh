#!/bin/sh
# Build component probes inside a disposable native image, never install FIC.
set -eu
src=${1:-/src}
out=${2:-/usr/local/bin}
inc="$src/build-env-full-debian12/fic/generated/include"
common="$src/fic-common/fic-core/src"
set -- -std=c++17 -Wall -Wextra -Werror -Wno-error=unused-variable -pthread \
    -I"$src/fic/src" -I"$src/fic-common/fic-core/include" -I"$inc"
g++ "$@" "$src/tests/integration/maintenance-lifecycle/MaskDriver.cpp" \
    "$src/fic/src/daemon/PackageUnitMasks.cpp" "$src/fic/src/daemon/DaemonInstanceLock.cpp" \
    "$common/fs/AtomicFileWriter.cpp" "$common/fs/SecureStateFile.cpp" \
    "$common/fs/RootControlledDirectory.cpp" -o "$out/m1-masks"
g++ "$@" "$src/tests/integration/maintenance-lifecycle/QuiescenceDriver.cpp" \
    "$src/fic/src/daemon/PackageWritersQuiescence.cpp" \
    "$src/fic/src/daemon/PackageUnitMasks.cpp" \
    "$src/fic/src/daemon/PackageWriterProcesses.cpp" \
    "$src/fic/src/daemon/StoppedWritersProof.cpp" \
    "$src/fic/src/daemon/DaemonInstanceLock.cpp" \
    "$src/fic/src/platform/PlatformExecutableResolver.cpp" \
    "$common/fs/AtomicFileWriter.cpp" "$common/fs/SecureStateFile.cpp" \
    "$common/fs/RootControlledDirectory.cpp" "$common/integrity/ContentDigest.cpp" \
    "$common/process/ProcessExecutor.cpp" "$common/process/ProcessPipeIo.cpp" \
    -lcrypto -o "$out/m1-quiescence"
g++ "$@" "$src/tests/fic/daemon/PackageUnknownWriterFixture.cpp" -o "$out/m1-unknown-writer"
g++ "$@" "$src/tests/fic/daemon/PackageWriterProcessesTests.cpp" \
    "$src/fic/src/daemon/PackageWriterProcesses.cpp" \
    "$src/fic/src/daemon/PackageWriterInventory.cpp" "$src/fic/src/daemon/DaemonInstanceLock.cpp" \
    "$common/fs/AtomicFileWriter.cpp" "$common/fs/SecureStateFile.cpp" \
    "$common/fs/RootControlledDirectory.cpp" "$common/integrity/ContentDigest.cpp" \
    -lcrypto -o "$out/m1-process-tests"
g++ "$@" "$src/tests/integration/maintenance-lifecycle/PackageDatabaseDriver.cpp" \
    "$src/fic/src/daemon/PackageDatabaseSnapshot.cpp" \
    "$src/fic/src/daemon/PackageManagerTransactionLock.cpp" "$src/fic/src/daemon/DaemonInstanceLock.cpp" \
    "$src/fic/src/platform/PlatformExecutableResolver.cpp" \
    "$common/fs/RootControlledDirectory.cpp" "$common/process/ProcessExecutor.cpp" \
    "$common/process/ProcessPipeIo.cpp" -o "$out/m1-package-db"
sh "$src/tests/integration/maintenance-lifecycle/build-coordinator-native.sh" "$src" "$out"
