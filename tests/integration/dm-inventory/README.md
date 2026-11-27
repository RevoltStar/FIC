# DM inventory native checks

Run `bash tests/integration/dm-inventory/run-native.sh IMAGE OUT` against an
image with systemd PID 1, systemctl, dbus and Python 3. The runner uses a
disposable privileged container, private cgroup namespace, no network, no
host bind mounts and no port bindings. The fixture changes only that container.

The fixture compares all unit-file names/states with and without --root=/,
including enabled/runtime/disabled/masked/alias/generated/transient/templates,
and confirms that a concrete template instance is included by list-units.
It also measures selected-property show per unit versus chunks of 32 and
checks a missing-unit partial response. These measurements do not change
FIC's production show implementation. A concurrent systemctl probe measures
manager responsiveness. Evidence JSON contains the measured systemd version.
Results apply to those disposable package snapshots and filesystem topology.
