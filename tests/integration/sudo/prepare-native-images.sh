#!/bin/sh
set -eu

# Every apt/package action is inside Podman; this script never invokes a host
# package manager. Use the repository's existing local builders as bases.
script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for platform in debian12 debian13 ubuntu2404 ubuntu2604 alt-p11; do
    case "$platform" in
        alt-p11) base=localhost/fic-rpm-builder:alt-p11 ;;
        *) base=localhost/fic-deb-builder:"$platform" ;;
    esac
    podman image exists "$base"
    podman build --pull=never --build-arg BASE_IMAGE="$base" \
        -f "$script_directory/Containerfile" \
        -t "localhost/fic-sudo-native:$platform" "$script_directory"
done

# Debian 12's cached builder has unusable permissions for non-root native
# authorization probes. Use the clean local distro base for the runtime.
for platform in debian12 alt-p11; do
    case "$platform" in
        debian12) base=docker.io/library/debian:12 ;;
        alt-p11) base=localhost/fic-sudo-native:alt-p11 ;;
    esac
    podman image exists "$base"
    podman build --pull=never --build-arg BASE_IMAGE="$base" \
        --build-arg PLATFORM="$platform" \
        -f "$script_directory/Containerfile.runtime" \
        -t "localhost/fic-sudo-native-runtime:$platform" "$script_directory"
done
