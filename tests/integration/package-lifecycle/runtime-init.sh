#!/bin/sh
# Disposable runtime image only. No host bind mounts; preserve writable cgroups.
set -eu
mount --rbind /sys /sys
mount -o remount,bind,ro /sys
mount --bind /proc/sys /proc/sys
mount -o remount,bind,ro /proc/sys
exec /lib/systemd/systemd
