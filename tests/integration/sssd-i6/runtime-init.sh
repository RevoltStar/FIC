#!/bin/sh
# Isolated fixture boundaries only; production never provisions them.
set -eu
mount --rbind /sys /sys
mount -o remount,bind,ro /sys
mount --bind /proc/sys /proc/sys
mount -o remount,bind,ro /proc/sys
mount --bind /etc /etc
mount --make-private /etc
mount --make-private /run
exec /sbin/init
