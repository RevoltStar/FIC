#!/usr/bin/env bash

# Validate the source identity for an official FIC release. The caller receives
# FIC_RELEASE_TAG, FIC_RELEASE_COMMIT, FIC_PRODUCT_VERSION and
# FIC_PACKAGE_VERSION only after all checks have succeeded.

fic_release_error() {
    printf 'Release contract error: %s\n' "$1" >&2
    return 1
}

fic_validate_release_checkout() {
    if [ "$#" -gt 1 ]; then
        fic_release_error "expected at most one repository path"
        return 1
    fi

    local repository="${1:-.}"
    local tag
    local tag_object_type
    local tag_commit
    local head_commit
    local status

    if ! git -C "$repository" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        fic_release_error "'$repository' is not a Git working tree"
        return 1
    fi

    status="$(git -C "$repository" status --porcelain --untracked-files=all)"
    if [ -n "$status" ]; then
        fic_release_error "the release working tree is dirty"
        return 1
    fi

    if ! tag="$(git -C "$repository" describe --tags --exact-match HEAD 2>/dev/null)"; then
        fic_release_error "HEAD must have an exact release tag"
        return 1
    fi
    if [[ ! "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?$ ]]; then
        fic_release_error "tag '$tag' is not v-prefixed SemVer"
        return 1
    fi

    tag_object_type="$(git -C "$repository" cat-file -t "refs/tags/$tag")"
    if [ "$tag_object_type" != "tag" ]; then
        fic_release_error "release tag '$tag' must be annotated"
        return 1
    fi

    tag_commit="$(git -C "$repository" rev-list -n 1 "$tag")"
    head_commit="$(git -C "$repository" rev-parse HEAD)"
    if [ "$tag_commit" != "$head_commit" ]; then
        fic_release_error "release tag '$tag' does not resolve to HEAD"
        return 1
    fi

    FIC_RELEASE_TAG="$tag"
    FIC_RELEASE_COMMIT="$head_commit"
    fic_configure_product_version "${tag#v}" || return 1

    if ! grep -Eq "^## \\[${FIC_PRODUCT_VERSION//./\\.}\\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" \
        "$repository/CHANGELOG.md"; then
        fic_release_error \
            "CHANGELOG.md must contain '## [$FIC_PRODUCT_VERSION] - YYYY-MM-DD'"
        return 1
    fi

    export FIC_RELEASE_TAG
    export FIC_RELEASE_COMMIT
}
