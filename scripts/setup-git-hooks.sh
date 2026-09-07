#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
hooks_dir="$repository_root/.githooks"

for hook_name in pre-commit pre-push; do
    hook_path="$hooks_dir/$hook_name"
    if [[ ! -f "$hook_path" ]]; then
        echo "Missing Git hook: $hook_path" >&2
        exit 1
    fi
    chmod u+x "$hook_path"
    if [[ ! -x "$hook_path" ]]; then
        echo "Git hook is not executable: $hook_path" >&2
        exit 1
    fi
done

git -C "$repository_root" config --local core.hooksPath .githooks

configured_hooks_path="$(git -C "$repository_root" config --local --get core.hooksPath)"
if [[ "$configured_hooks_path" != ".githooks" ]]; then
    echo "Failed to configure core.hooksPath" >&2
    exit 1
fi

echo "Git hooks enabled from $hooks_dir"
