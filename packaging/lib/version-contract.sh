#!/usr/bin/env bash

# Shared product/package version contract. Call fic_configure_product_version
# with exactly one explicit product SemVer before using FIC_PRODUCT_VERSION or
# FIC_PACKAGE_VERSION.

fic_version_error() {
    printf 'Version contract error: %s\n' "$1" >&2
    return 1
}

fic_configure_product_version() {
    if [ "$#" -ne 1 ] || [ -z "$1" ]; then
        fic_version_error \
            "an explicit product version is required (for example 2.0.0-rc.1)"
        return 1
    fi

    local version="$1"
    local core
    local prerelease
    local identifier
    local identifiers=()

    if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?$ ]]; then
        fic_version_error \
            "product version must be SemVer without build metadata, got '$version'"
        return 1
    fi

    core="${version%%-*}"
    if [ "$core" != "$version" ]; then
        prerelease="${version#*-}"
        IFS='.' read -r -a identifiers <<< "$prerelease"
        for identifier in "${identifiers[@]}"; do
            if [[ "$identifier" =~ ^0[0-9]+$ ]]; then
                fic_version_error \
                    "numeric prerelease identifiers must not have leading zeroes: '$identifier'"
                return 1
            fi
        done
        FIC_PACKAGE_VERSION="${core}~${prerelease}"
    else
        FIC_PACKAGE_VERSION="$version"
    fi

    FIC_PRODUCT_VERSION="$version"
    export FIC_PRODUCT_VERSION
    export FIC_PACKAGE_VERSION
}
