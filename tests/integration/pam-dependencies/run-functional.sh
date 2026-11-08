#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: run-functional.sh TAG BUILD_DIR'; exit 2; }
tag=$1
case "$tag" in debian12|debian13|ubuntu2404|ubuntu2604) image=fic-pam-i6-native:$tag;; alt-p11) image=fic-pam-i6-native:alt-p11;; *) exit 2;; esac
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
build=$(realpath "$2");out="$repo/build-pam-i6/$tag";mkdir -p "$out"
docker image inspect "$image" --format '{{.Id}}' > "$out/image-id.txt"
docker run --rm --network none -e FIC_I6_SOURCE="$(cat "$repo/build-pam-i6/i6-source-$tag.after")" -e FIC_I6_BASE="$(git -C "$repo" rev-parse HEAD)" -v "$repo:/src:ro" -v "$build:/build:ro" -v "$out:/evidence" "$image" sh -ec '
 cc -Wall -Wextra /src/tests/integration/pam-c2/fic_pam_probe.c -lpam -o /tmp/fic-i6-probe
 chown 0:0 /tmp/fic-i6-probe;chmod 4755 /tmp/fic-i6-probe
 if command -v dpkg-query >/dev/null; then
  dpkg-query -W > /evidence/packages.txt
  # Install the same packaged neutral infrastructure, never stock templates.
  DEBIAN_FRONTEND=noninteractive pam-auth-update --disable pwquality
  cp /src/packaging/deb/pam-slots/* /etc/pam.d/
  cp /src/packaging/deb/pam-configs/fic-password-*-hook /usr/share/pam-configs/
  cp /src/packaging/deb/pam-configs/fic-faillock-hook-* /usr/share/pam-configs/
  for profile in fic-faillock-hook-preauth fic-faillock-hook-authfail fic-faillock-hook-authsucc fic-faillock-hook-account; do
   DEBIAN_FRONTEND=noninteractive pam-auth-update --enable "$profile"
  done
 else
  rpm -qa > /evidence/packages.txt
  control system-auth local
  cp /build/fic/pam_fic_pwtxn.so /lib64/security/pam_fic_pwtxn.so
  cp /src/fic/src/resources/pam/fic-pwhistory.conf /etc/security/fic-pwhistory.conf
 fi
 mkdir -p /evidence/baseline-pam
 cp -a /etc/pam.d/. /evidence/baseline-pam/
 python3 /src/tests/integration/pam-dependencies/native-functional.py "$1"
 ' sh "$tag" > "$out/run.log" 2>&1
