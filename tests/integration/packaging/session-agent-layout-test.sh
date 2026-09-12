#!/usr/bin/env bash
set -euo pipefail

BUILD_DIR="${1:?build directory is required}"
STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fic-session-agent-layout.XXXXXX")"
trap 'rm -rf "$STAGE_DIR"' EXIT

fail() {
    echo "session-agent layout test failed: $1" >&2
    exit 1
}

DESTDIR="$STAGE_DIR" cmake --install "$BUILD_DIR" \
    --component fic-session-agent >/dev/null

agent_dir="$STAGE_DIR/usr/libexec/fic"
agent="$agent_dir/fic-session-agent"
helper="$agent_dir/fic-xfconf-inspect"
desktop="$STAGE_DIR/etc/xdg/autostart/fic-session-agent.desktop"
old_agent="$STAGE_DIR/opt/fic/bin/fic-session-agent"

[ -d "$agent_dir" ] || fail "public executable directory is missing"
[ -f "$agent" ] || fail "public executable is missing"
[ "$(stat -c '%a' "$agent_dir")" = "755" ] ||
    fail "public executable directory mode is not 0755"
[ "$(stat -c '%a' "$agent")" = "755" ] ||
    fail "public executable mode is not 0755"
[ -x "$agent" ] || fail "public executable is not executable by the test user"
[ -f "$helper" ] || fail "xfconf inspect helper is missing"
[ "$(stat -c '%a' "$helper")" = "755" ] ||
    fail "xfconf inspect helper mode is not 0755"
[ -x "$helper" ] || fail "xfconf inspect helper is not executable by the test user"
"$helper" --self-test || fail "xfconf inspect helper protocol self-test failed"
[ ! -e "$old_agent" ] || fail "private-tree executable copy is present"
[ -f "$desktop" ] || fail "XDG Autostart desktop file is missing"
grep -Fxq 'Exec=/usr/libexec/fic/fic-session-agent' "$desktop" ||
    fail "XDG Autostart does not use the exact public executable path"

echo "session-agent layout tests passed"
