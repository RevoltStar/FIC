#!/usr/bin/env bash
# Run in disposable target containers with Xvfb, xauth and runuser installed.
set -euo pipefail
[ "${FIC_DISPOSABLE_GUI_VARIANT_TEST:-}" = 1 ] || {
    echo 'Run this test only in a disposable distribution container' >&2
    exit 2
}
family="${1:?deb or rpm required}"
directory="$(realpath "${2:?directory of matching platform packages required}")"
case "$family" in
    deb) package_field() { dpkg-deb -f "$1" "$2"; }; extension=deb; name_field=Package ;;
    rpm)
        package_field() { rpm -qp --queryformat "%{$2}" "$1"; }
        extension=rpm; name_field=NAME ;;
    *) exit 2 ;;
esac

package() {
    local file name
    local matches=()
    for file in "$directory"/*."$extension"; do
        name="$(package_field "$file" "$name_field")" || return 1
        if [ "$name" = "$1" ]; then matches+=("$file"); fi
    done
    if [ "${#matches[@]}" -ne 1 ]; then
        echo "Expected exactly one $1 package" >&2
        return 1
    fi
    printf '%s\n' "${matches[0]}"
}

bundled="$(package fic-gui)"
system="$(package fic-gui-system-qt)"
fic="$(package fic)"
dick="$(package fic-dick)"
if [ "$family" = deb ]; then
    version="$(package_field "$fic" Version)"
    for file in "$bundled" "$system" "$dick"; do
        [ "$(package_field "$file" Version)" = "$version" ]
    done
    [ "$(package_field "$bundled" Conflicts)" = fic-gui-system-qt ]
    [ "$(package_field "$system" Conflicts)" = fic-gui ]
    for file in "$bundled" "$system"; do
        depends="$(package_field "$file" Depends)"
        grep -Fq "fic (= $version)" <<<"$depends"
        grep -Fq "fic-dick (= $version)" <<<"$depends"
    done
    ! grep -Eq '(^|, )(libqt6|qt6-)' <<<"$(package_field "$bundled" Depends)" || exit 1
    grep -Eq '(^|, )libqt6widgets6' <<<"$(package_field "$system" Depends)"
    payload="$(dpkg-deb --fsys-tarfile "$system" | tar -tf -)"
    elf_digest() {
        dpkg-deb --fsys-tarfile "$1" | tar -xOf - "./opt/fic/bin/$2" | sha256sum
    }
    bundled_elf="$(elf_digest "$bundled" fic-gui.real)"
    system_elf="$(elf_digest "$system" fic-gui)"
    [ "$bundled_elf" = "$system_elf" ]
    installed_core() { dpkg-query -W -f='${db:Status-Status} ${Version}\n' fic fic-dick; }
    install_packages() { apt-get install -y --no-install-recommends "$@"; }
    purge_gui() { apt-get purge -y fic-gui-system-qt; }
else
    version="$(rpm -qp --queryformat '%{VERSION}-%{RELEASE}' "$fic")"
    for file in "$bundled" "$system" "$dick"; do
        [ "$(rpm -qp --queryformat '%{VERSION}-%{RELEASE}' "$file")" = "$version" ]
    done
    [ "$(rpm -qp --conflicts "$bundled")" = fic-gui-system-qt ]
    [ "$(rpm -qp --conflicts "$system")" = fic-gui ]
    [ "$(package_field "$system" LICENSE)" = SUL-1.0 ]
    for file in "$bundled" "$system"; do
        requires="$(rpm -qp --requires "$file")"
        grep -Fxq "fic = $version" <<<"$requires"
        grep -Fxq "fic-dick = $version" <<<"$requires"
    done
    ! grep -q '^libQt6' <<<"$(rpm -qp --requires "$bundled")" || exit 1
    grep -q '^libQt6Widgets\.so\.6' <<<"$(rpm -qp --requires "$system")"
    payload="$(rpm -qpl "$system")"
    installed_core() { rpm -q fic fic-dick; }
    install_packages() { apt-get install -y "$@"; }
    purge_gui() { apt-get remove -y fic-gui-system-qt; }
fi
if grep -Eq '(^|/)(qt\.conf|fic-gui\.real|third-party-components\.json)$|/opt/fic/qt(/|$)|/libQt6|/plugins/' <<<"$payload"; then
    echo 'Private Qt payload found in system GUI package' >&2
    exit 1
fi

check_gui() {
    local variant="$1" output expected paths count=0 path
    [ "$(readlink /bin/fic-gui)" = /opt/fic/bin/fic-gui ]
    [ "$(stat -c '%U:%G:%a:%h' /opt/fic/bin/fic-gui)" = root:fic:750:1 ]
    if [ "$variant" = bundled ]; then
        [ "$(stat -c '%U:%G:%a:%h' /opt/fic/bin/fic-gui.real)" = root:fic:750:1 ]
        [ -f /opt/fic/bin/qt.conf ]
        [ -d /opt/fic/qt ]
        expected='^/opt/fic/qt/lib/'
    else
        [ ! -e /opt/fic/bin/fic-gui.real ]
        [ ! -e /opt/fic/bin/qt.conf ]
        [ ! -e /opt/fic/qt ]
        [ ! -e /usr/share/doc/fic-gui/third-party-components.json ]
        expected='^/(usr/)?lib(64)?/'
    fi
    runuser -u ficgui-member -- /bin/fic-gui --license-info
    if runuser -u ficgui-outsider -- /bin/fic-gui --license-info; then
        echo 'Unexpected GUI access outside the fic group' >&2
        exit 1
    fi
    if ! output="$(runuser -u ficgui-member -- xvfb-run -a env \
            -u FIC_QT_ROOT -u LD_LIBRARY_PATH -u QT_PLUGIN_PATH -u QT_QPA_PLATFORM_PLUGIN_PATH \
            QT_QPA_PLATFORM=xcb LD_DEBUG=libs /bin/fic-gui --gui-smoke-test 2>&1)"; then
        printf '%s\n' "$output" >&2
        return 1
    fi
    grep -Fxq 'qpa-platform=xcb' <<<"$output"
    grep -Fxq 'jpeg-plugin=ok' <<<"$output"
    grep -Eq "^qt-core-path=${expected#^}" <<<"$output"
    paths="$(sed -nE 's/.*calling init: (.*\/(libQt6[^/]*\.so[^/]*|libqxcb\.so|libqjpeg\.so))$/\1/p' <<<"$output")"
    for path in libQt6Core libQt6Gui libQt6Widgets libqxcb libqjpeg; do
        grep -Eq "/$path\\.so" <<<"$paths"
    done
    if [ "$variant" = bundled ]; then expected='^/opt/fic/qt/(lib|plugins)/'; fi
    while IFS= read -r path; do
        if ! [[ "$path" =~ $expected ]]; then
            echo "Unexpectedly loaded $path for $variant Qt" >&2
            return 1
        fi
        count=$((count + 1))
    done <<<"$paths"
    echo "PASS $variant GUI smoke and group permissions ($count Qt objects)"
}

# Run each clean scenario in a fresh instance of the container.
mkdir -p /var/cache/apt/archives/partial
apt-get update
case "${FIC_GUI_TEST_SCENARIO:-switch}" in
    switch) first="$bundled" ;;
    remove) first="$system" ;;
    *) exit 2 ;;
esac
install_packages "$fic" "$dick" "$first"
getent group fic >/dev/null
useradd -M -g fic ficgui-member
useradd -M -U ficgui-outsider
core_before="$(installed_core)"
if [ "$first" = "$bundled" ]; then
    check_gui bundled
    install_packages "$system" fic-gui-
    check_gui system
    install_packages "$bundled" fic-gui-system-qt-
    check_gui bundled
else
    check_gui system
    purge_gui
    for path in /bin/fic-gui /opt/fic/bin/fic-gui /opt/fic/bin/fic-gui.real /opt/fic/bin/qt.conf /opt/fic/qt; do
        [ ! -e "$path" ]
        [ ! -L "$path" ]
    done
fi
[ "$(installed_core)" = "$core_before" ]
echo "PASS $family GUI transaction: ${FIC_GUI_TEST_SCENARIO:-switch}"
