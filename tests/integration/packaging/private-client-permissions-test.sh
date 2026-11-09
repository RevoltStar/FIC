#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../.." && pwd)
work=$(mktemp -d)
export STAGING_BASE="$work/stage" BUILD_ROOT="$work/build" DIST_DIR="$work/dist" BUILD_JOBS=1
mkdir -p "$STAGING_BASE"
source "$repo/packaging/deb/build-fic-debian12-deb.sh" 0.1.1
trap 'rm -rf "$work"' EXIT
for name in fic-cli fic-gui; do
 mkdir -p "$work/$name/DEBIAN"
 write_symlink_postinst "$work/$name" "$name" "/opt/fic/bin/$name"
 sh -n "$work/$name/DEBIAN/postinst"
 grep -Fq 'chmod 2750 /opt/fic /opt/fic/bin' "$work/$name/DEBIAN/postinst"
 grep -Fq "chmod 0750 /opt/fic/bin/$name" "$work/$name/DEBIAN/postinst"
 if grep -Eq '(chown|chmod).* (-R|--recursive)|find /opt/fic' "$work/$name/DEBIAN/postinst"; then exit 1; fi
 done
if write_symlink_postinst "$work/fic-cli" fic /opt/fic/bin/fic; then exit 1; fi
# The actual file-list producer is tested independently of host rpm tools.
ROOT_DIR="$repo" source /dev/stdin <<EOF_RPM
$(sed -n '/^write_file_list() {/,/^}/p' "$repo/packaging/rpm/build-fic-alt-p11-rpm.sh")
EOF_RPM
mkdir -p "$work/rpm/opt/fic/bin" "$work/rpm/opt/fic/config"
touch "$work/rpm/opt/fic/bin/fic-cli" "$work/rpm/opt/fic/bin/fic-gui" "$work/rpm/opt/fic/bin/fic-gui.real"
write_file_list "$work/rpm" "$work/files"
grep -Fxq '%dir %attr(2750,root,fic) /opt/fic/bin' "$work/files"
for name in fic-cli fic-gui fic-gui.real; do grep -Fxq "%attr(0750,root,fic) /opt/fic/bin/$name" "$work/files"; done
if grep -Eq '^%dir /opt/fic$|^%dir /opt/fic/config$' "$work/files"; then exit 1; fi
echo 'PASS production DEB postinst generation and RPM file-list attributes'
