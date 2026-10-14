#!/bin/bash
set -euo pipefail
script=$(cd "$(dirname "$0")" && pwd)
# Existing builder/runtime preparation is described in ../sudo/. Debian12
# and ALT use those tested runtimes; these three need distro-native adduser.
for row in debian13 ubuntu2404 ubuntu2604; do
 podman image exists "localhost/fic-sudo-native:$row"
 podman build --pull=never --build-arg BASE_IMAGE="localhost/fic-sudo-native:$row" \
  -f "$script/Containerfile.runtime" -t "localhost/fic-user-creation-native-runtime:$row" "$script"
done
