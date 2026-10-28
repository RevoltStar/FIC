#!/usr/bin/env bash
# Run only in a disposable BUILD container with /build writable. Not on host.
set -euo pipefail
[[ -e /.dockerenv && ${FIC_SSSD_RESEARCH:-} == 1 ]] || exit 2
mkdir -p /build/source
cd /build/source
if [[ -e /etc/altlinux-release ]]; then
 echo 'rpm-src [p11] https://distrib-coffee.ipsl.jussieu.fr/pub/linux/altlinux p11/branch/x86_64 classic' > /etc/apt/sources.list.d/sssd-research-source.list
 apt-get update
 apt-get source --download-only sssd
 expected_srpm=$(rpm -q --qf '%{SOURCERPM}' sssd)
 [[ -f "$expected_srpm" ]] || { echo "Source archive does not match installed SSSD: $expected_srpm" >&2; exit 1; }
 for p in *.src.rpm; do rpm2cpio "$p" | cpio -id; done
 for p in sssd-*.tar sssd-*.tar.*; do [[ -f "$p" ]] && tar -xf "$p"; done
 source_dir=$(find . -maxdepth 1 -type d -name "sssd-*" | head -n 1)
 (cd "$source_dir"; patch -p1 < ../sssd-*-alt.patch)
else
 for p in /etc/apt/sources.list.d/*.sources; do [[ -f "$p" ]] || continue; sed 's/^Types: deb$/Types: deb-src/' "$p" > /etc/apt/sources.list.d/sssd-research-"$(basename "$p")"; done
 if [[ -f /etc/apt/sources.list ]]; then sed -n 's/^deb /deb-src /p' /etc/apt/sources.list > /etc/apt/sources.list.d/sssd-research.list; fi
 apt-get update
 version=$(dpkg-query -W -f='${source:Version}' sssd-common)
 apt-get source "sssd=$version"
fi
sha256sum ./*.dsc ./*.tar.* ./*.src.rpm 2>/dev/null || true
