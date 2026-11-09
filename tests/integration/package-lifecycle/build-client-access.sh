#!/usr/bin/env bash
# Repackage unchanged native client payloads with CURRENT production packaging
# functions. This is a permissions regression gate, not a release rebuild.
set -euo pipefail
[[ -f /run/.containerenv || -f /.dockerenv ]] || exit 77
format=${1:?deb or rpm}; inputs=${2:?artifact directory}; output=${3:?output directory}; row=${4:?distro tag}
repo=$(cd "$(dirname "$0")/../../.." && pwd)
work=$(mktemp -d)
export STAGING_BASE="$work/staging" RPM_TOPDIR="$work/rpmbuild" DIST_DIR="$output" BUILD_JOBS=1
mkdir -p "$STAGING_BASE" "$output" "$output/upgrades"
if [[ $format == deb ]]; then
 source "$repo/packaging/deb/build-fic-debian12-deb.sh" 0.1.1
else
 source "$repo/packaging/rpm/build-fic-alt-p11-rpm.sh" 0.1.1
 init_rpm_tree
fi
for version in 0.1.1 0.1.2; do
 PACKAGE_VERSION=$version
 DIST_DIR=$output
 [[ $version == 0.1.1 ]] || DIST_DIR="$output/upgrades"
 for name in fic-cli fic-gui; do
  stage="$work/$name-$version"
  mkdir -p "$stage"
  if [[ $format == deb ]]; then
   candidates=("$inputs/${name}_"*"_${row}_amd64.deb")
   [[ ${#candidates[@]} == 1 && -f ${candidates[0]} ]]
   sha256sum "${candidates[0]}"
   dpkg-deb -R "${candidates[0]}" "$stage"
   sed -i "s/^Version:.*/Version: $version/" "$stage/DEBIAN/control"
   write_common_preinst "$stage"
   write_symlink_postinst "$stage" "$name" "/opt/fic/bin/$name"
   write_symlink_prerm "$stage" "$name" "/opt/fic/bin/$name"
   chmod 0750 "$stage/opt/fic/bin/$name"
   [[ $name != fic-gui ]] || chmod 0750 "$stage/opt/fic/bin/fic-gui.real"
   sha256sum "$stage/opt/fic/bin/$name"
   [[ $name != fic-gui ]] || sha256sum "$stage/opt/fic/bin/fic-gui.real"
   build_deb_package "$stage" "$DIST_DIR/${name}_${version}_${row}_amd64.deb"
  else
   input="$inputs/${name}-0.0.0~alpha-1.altp11.x86_64.rpm"
   sha256sum "$input"
   rpm2cpio "$input" | (cd "$stage"; cpio -idm --quiet --no-absolute-filenames)
   sha256sum "$stage/opt/fic/bin/$name"
   [[ $name != fic-gui ]] || sha256sum "$stage/opt/fic/bin/fic-gui.real"
   build_rpm_package "$stage" "$name" 'FIC private-client access regression' \
    'Unchanged native FIC client payload; current production metadata/scriptlets.' '' \
    "$(common_pre_script)" "$(symlink_post_script "$name" "/opt/fic/bin/$name")" \
    "$(symlink_preun_script "$name" "/opt/fic/bin/$name")"
  fi
 done
done
