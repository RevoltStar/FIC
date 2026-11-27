# DM inventory native checks

Run `bash tests/integration/dm-inventory/run-native.sh IMAGE OUT` against an
image with systemd PID 1, systemctl, dbus and Python 3. The runner uses a
disposable privileged container, private cgroup namespace, no network, no
host bind mounts and no port bindings. The fixture changes only that container.

The fixture compares all unit-file names/states with and without --root=/,
including enabled/runtime/disabled/masked/alias/generated/transient/templates,
and confirms that a concrete template instance is included by list-units.
It also measures selected-property show per unit versus chunks of 32 and
checks a missing-unit partial response. The original two-argument runner is a
transport research comparison. A concurrent systemctl probe measures
manager responsiveness. Evidence JSON contains the measured systemd version.
Results apply to those disposable package snapshots and filesystem topology.

## Production batching validation

Configure this directory with FIC_TARGET_PLATFORM and FIC_DM_BASELINE_SOURCE
pointing to DisplayManagerInventory.cpp from commit 3fb17c7d. Build the two
dm_inventory_individual and dm_inventory_batch targets in the target distro.

Run the same runner with its optional third argument naming that binary
directory. It copies both drivers into the disposable container, prepares
the unit fixtures, and runs batch-native.py with three alternating repetitions.
Both executables use actual production inventory source and ProcessExecutor.
The Run seam invokes real systemctl/loginctl; it does not exercise the
PlatformExecutableResolver trust constructor. Executable trust behavior
continues to have its existing deterministic tests.

Each production snapshot must match, and every requested union member is
compared without collapsing aliases into an Id-only map. Every requested
name's property projection is also compared through real show calls. Repeated
canonical/alias names are also checked as raw blocks. A synthetic enumeration
entry models a disappearing file, but its not-found property reply comes
from the real manager and is parsed by production code. The runner checks
coverage and classification, process count, property/full elapsed time,
parallel probe maximum and 250ms exceedances. No cold-HDD claim is made.

The fixture-only /usr/local/bin/sddm executes sleep behind an unrelated unit
name. This tests classification without installing or running a real DM.
The runtime container has no network or host binds. Builder containers may
use read-only source and a writable build directory.

Example build inside a matching distro builder (source mounted read-only):

```bash
git show 3fb17c7d:fic/src/modules/oss/display_manager/DisplayManagerInventory.cpp > /tmp/individual.cpp
cmake -S tests/integration/dm-inventory -B /tmp/dm-build \
  -DFIC_TARGET_PLATFORM=debian-12 -DFIC_DM_BASELINE_SOURCE=/tmp/individual.cpp
cmake --build /tmp/dm-build -j2
bash tests/integration/dm-inventory/run-native.sh IMAGE /tmp/dm-evidence /tmp/dm-build
```

Accepted native results for the production change are in `batch-evidence/`.
They contain all requested names, exact systemd versions, fixture proofs and six
measurement records per platform. Durations include the parallel control probe;
compare the two modes in the same file, not timings from separate experiments.
See [validation](../../../docs/graphical-scope-validation.md) for the table.

The batch argv contains at most 32 validated names of at most 256 bytes (less
than 8.5 KiB of arguments); native ARG_MAX was 2097152 on all five containers.
ProcessExecutor still enforces its 5-second timeout and 4 MiB combined output
limit. Neither is increased for DM, and outputLimitExceeded cannot be SUCCESS.
Measured output sizes and maximum single-call durations are recorded, but are
not upper bounds for arbitrary administrator-defined units.
