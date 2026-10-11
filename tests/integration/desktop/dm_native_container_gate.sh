#!/bin/sh
# Run only in a disposable container with an explicitly mounted native probe.
set -eu
[ "${FIC_NATIVE_DM_PROBE:-}" = container-only ] && [ -f /.dockerenv ] && [ "$(id -u)" = 0 ] || exit 77
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update -qq
qt_package=libqt6core6
if apt-cache show libqt6core6t64 >/dev/null 2>&1; then qt_package=libqt6core6t64; fi
apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 install -y --no-install-recommends sddm gdm3 lightdm "$qt_package" > /tmp/dm-install.log 2>&1 || { tail -n 25 /tmp/dm-install.log; exit 1; }
version=$(dpkg-query --show '--showformat=${Version}' sddm)
case "$version" in *0.19.*) tag=0.19.0; qtdev=qtbase5-dev; qtcore=Qt5Core;; *0.20.*) tag=0.20.0; qtdev=qt6-base-dev; qtcore=Qt6Core;; *0.21.*) tag=0.21.0; qtdev=qt6-base-dev; qtcore=Qt6Core;; *) echo "NOT VERIFIED: unsupported SDDM source version $version"; exit 1;; esac
apt-get install -y --no-install-recommends g++ pkg-config "$qtdev" >> /tmp/dm-install.log 2>&1 || { tail -n 25 /tmp/dm-install.log; exit 1; }
mkdir -p /run/fic-dm-probe/native-source
cp "/upstream/ConfigReader-$tag.cpp" /run/fic-dm-probe/native-source/ConfigReader.cpp
cp "/upstream/ConfigReader-$tag.h" /run/fic-dm-probe/native-source/ConfigReader.h
c++ -std=c++17 -fPIC /run/fic-dm-probe/native-source/ConfigReader.cpp /src/tests/integration/desktop/sddm-native-reader.cpp -I/run/fic-dm-probe/native-source $(pkg-config --cflags --libs "$qtcore") -o /run/fic-dm-probe/sddm-native-reader
dpkg-query --show '--showformat=${binary:Package}\t${Version}\n' sddm gdm3 lightdm "$qt_package"
strings /usr/sbin/gdm3 | grep -E "(/etc/|/run/).*gdm|custom.conf|daemon.conf" || true
/probe/display_manager_native_probe
