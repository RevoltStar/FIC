#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT_DIR/packaging/lib/version-contract.sh"
source "$ROOT_DIR/packaging/lib/release-contract.sh"

usage() {
    echo "Usage: $0 [--verify-only]" >&2
}

VERIFY_ONLY=0
case "${1:-}" in
    "")
        ;;
    --verify-only)
        VERIFY_ONLY=1
        ;;
    *)
        usage
        exit 2
        ;;
esac
if [ "$#" -gt 1 ]; then
    usage
    exit 2
fi

fic_validate_release_checkout "$ROOT_DIR"
echo "Verified release source: $FIC_RELEASE_TAG ($FIC_RELEASE_COMMIT)"

if [ "$VERIFY_ONLY" -eq 1 ]; then
    exit 0
fi

if [ -z "${FIC_CORRESPONDING_SOURCE_DIR:-}" ] || \
   [ ! -d "$FIC_CORRESPONDING_SOURCE_DIR" ]; then
    echo "FIC_CORRESPONDING_SOURCE_DIR must name the retained source artifact set" >&2
    exit 1
fi
FIC_CORRESPONDING_SOURCE_DIR="$(cd "$FIC_CORRESPONDING_SOURCE_DIR" && pwd)"

SNAPSHOT_PARENT="$(mktemp -d /tmp/fic-release-XXXXXX)"
SNAPSHOT_DIR="$SNAPSHOT_PARENT/source"
OUTPUT_PARENT="$ROOT_DIR/dist/release"
OUTPUT_DIR="$OUTPUT_PARENT/$FIC_PRODUCT_VERSION"
OUTPUT_STAGING=

cleanup() {
    rm -rf "$SNAPSHOT_PARENT"
    if [ -n "$OUTPUT_STAGING" ] && [ -d "$OUTPUT_STAGING" ]; then
        rm -rf "$OUTPUT_STAGING"
    fi
}
trap cleanup EXIT

if [ -e "$OUTPUT_DIR" ]; then
    echo "Release output already exists: $OUTPUT_DIR" >&2
    exit 1
fi

mkdir -p "$SNAPSHOT_DIR"
git -C "$ROOT_DIR" archive --format=tar "$FIC_RELEASE_COMMIT" |
    tar -x -C "$SNAPSHOT_DIR"

export FIC_BUILD_COMMIT="$FIC_RELEASE_COMMIT"
export FIC_RELEASE_TAG
export FIC_RELEASE_BUILD=ON
export DIST_DIR=/workspace/dist

"$SNAPSHOT_DIR/packaging/deb/build-fic-debian12-deb-docker.sh" "$FIC_PRODUCT_VERSION"
"$SNAPSHOT_DIR/packaging/deb/build-fic-debian13-deb-docker.sh" "$FIC_PRODUCT_VERSION"
"$SNAPSHOT_DIR/packaging/deb/build-fic-ubuntu2404-deb-docker.sh" "$FIC_PRODUCT_VERSION"
"$SNAPSHOT_DIR/packaging/deb/build-fic-ubuntu2604-deb-docker.sh" "$FIC_PRODUCT_VERSION"
"$SNAPSHOT_DIR/packaging/rpm/build-fic-alt-p11-rpm-docker.sh" "$FIC_PRODUCT_VERSION"

mapfile -d '' ARTIFACTS < <(
    find "$SNAPSHOT_DIR/dist" -maxdepth 1 -type f \
        \( -name '*.deb' -o -name '*.rpm' \) -print0 | sort -z
)
if [ "${#ARTIFACTS[@]}" -ne 25 ]; then
    echo "Expected 25 release packages, found ${#ARTIFACTS[@]}" >&2
    exit 1
fi

mapfile -d '' THIRD_PARTY_MANIFESTS < <(
    find "$SNAPSHOT_DIR/dist" -maxdepth 1 -type f \
        -name 'fic-gui*.third-party-components.json' -print0 | sort -z
)
if [ "${#THIRD_PARTY_MANIFESTS[@]}" -ne 5 ]; then
    echo "Expected 5 fic-gui third-party manifests, found ${#THIRD_PARTY_MANIFESTS[@]}" >&2
    exit 1
fi

source_verify_args=()
for manifest in "${THIRD_PARTY_MANIFESTS[@]}"; do
    source_verify_args+=(--manifest "$manifest")
done
python3 "$SNAPSHOT_DIR/packaging/lib/corresponding-source.py" \
    --source-dir "$FIC_CORRESPONDING_SOURCE_DIR" \
    "${source_verify_args[@]}"

current_head="$(git -C "$ROOT_DIR" rev-parse HEAD)"
current_status="$(git -C "$ROOT_DIR" status --porcelain --untracked-files=all)"
if [ "$current_head" != "$FIC_RELEASE_COMMIT" ] || [ -n "$current_status" ]; then
    echo "Source checkout changed during the release build" >&2
    exit 1
fi

mkdir -p "$OUTPUT_PARENT"
OUTPUT_STAGING="$(mktemp -d "$OUTPUT_PARENT/.${FIC_PRODUCT_VERSION}-XXXXXX")"
for artifact in "${ARTIFACTS[@]}"; do
    cp "$artifact" "$OUTPUT_STAGING/"
done
mkdir -p "$OUTPUT_STAGING/compliance-manifests" "$OUTPUT_STAGING/corresponding-source"
for manifest in "${THIRD_PARTY_MANIFESTS[@]}"; do
    cp "$manifest" "$OUTPUT_STAGING/compliance-manifests/"
done
cp -a "$FIC_CORRESPONDING_SOURCE_DIR"/. "$OUTPUT_STAGING/corresponding-source/"

MANIFEST="$OUTPUT_STAGING/release-manifest.json"
{
    printf '{\n'
    printf '  "product_version": "%s",\n' "$FIC_PRODUCT_VERSION"
    printf '  "package_version": "%s",\n' "$FIC_PACKAGE_VERSION"
    printf '  "tag": "%s",\n' "$FIC_RELEASE_TAG"
    printf '  "commit": "%s",\n' "$FIC_RELEASE_COMMIT"
    printf '  "corresponding_source_index_sha256": "%s",\n' \
        "$(sha256sum "$OUTPUT_STAGING/corresponding-source/corresponding-source.json" | cut -d ' ' -f 1)"
    printf '  "artifacts": [\n'
    for index in "${!ARTIFACTS[@]}"; do
        artifact_name="$(basename "${ARTIFACTS[$index]}")"
        artifact_hash="$(sha256sum "$OUTPUT_STAGING/$artifact_name" | cut -d ' ' -f 1)"
        separator=,
        if [ "$index" -eq "$((${#ARTIFACTS[@]} - 1))" ]; then
            separator=
        fi
        printf '    {"file": "%s", "sha256": "%s"}%s\n' \
            "$artifact_name" "$artifact_hash" "$separator"
    done
    printf '  ]\n'
    printf '}\n'
} > "$MANIFEST"

if [ -e "$OUTPUT_DIR" ]; then
    echo "Release output appeared during the build: $OUTPUT_DIR" >&2
    exit 1
fi
mv -T "$OUTPUT_STAGING" "$OUTPUT_DIR"
OUTPUT_STAGING=

echo "Release artifacts created in $OUTPUT_DIR"
