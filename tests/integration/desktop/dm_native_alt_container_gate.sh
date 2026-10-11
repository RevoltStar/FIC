#!/bin/sh
# Disposable ALT p11 only; no service/daemon is started by this probe.
set -eu
[ "${FIC_NATIVE_DM_PROBE:-}" = container-only ] && [ -f /.dockerenv ] && [ "$(id -u)" = 0 ] || exit 77
export LC_ALL=C
apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=20 update -qq
# Explicit cache recovery still requires native apt hashes/signatures and fails
# if any archive is missing; it never accepts a partial/unchecked package.
fic_dm_download_option=''
if [ -f /run/fic-dm-native-cache-ready ]; then fic_dm_download_option=--no-download; fi
if [ -s /run/fic-dm-native-print-uris ]; then
    apt-get --print-uris --download-only -y install sddm gdm lightdm binutils gcc-c++ pkg-config qt6-base-devel
    exit 77 # Diagnostic metadata only; no native provider check ran.
fi
apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=20 $fic_dm_download_option install -y sddm gdm lightdm binutils gcc-c++ pkg-config qt6-base-devel > /tmp/dm-install.log 2>&1 || { tail -n 25 /tmp/dm-install.log; exit 1; }
version=$(rpm -q --qf '%{VERSION}' sddm)
case "$version" in 0.20.*) tag=0.20.0;; 0.21.*) tag=0.21.0;; *) echo "NOT VERIFIED: unsupported SDDM source version $version"; exit 1;; esac
mkdir -p /run/fic-dm-probe/native-source
cp "/upstream/ConfigReader-$tag.cpp" /run/fic-dm-probe/native-source/ConfigReader.cpp
cp "/upstream/ConfigReader-$tag.h" /run/fic-dm-probe/native-source/ConfigReader.h
c++ -std=c++17 -fPIC /run/fic-dm-probe/native-source/ConfigReader.cpp /src/tests/integration/desktop/sddm-native-reader.cpp -I/run/fic-dm-probe/native-source $(pkg-config --cflags --libs Qt6Core) -o /run/fic-dm-probe/sddm-native-reader
rpm -q sddm gdm lightdm qt6-base-devel
strings /usr/sbin/gdm | grep -E '(/etc/|/run/).*gdm|custom.conf|daemon.conf' || true
strings /usr/bin/sddm | grep 'sddm.conf' || true
/probe/display_manager_native_probe
