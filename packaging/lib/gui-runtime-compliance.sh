#!/usr/bin/env bash

# Shared fic-gui runtime bundling and compliance helpers. The caller must set
# ROOT_DIR, STAGING_BASE, GUI_QT_BUNDLE_ROOT and FIC_GUI_BUILD_DIR.

fic_gui_runtime_error() {
    printf 'fic-gui runtime compliance error: %s\n' "$1" >&2
    return 1
}

fic_gui_package_owner() {
    local family="$1"
    local source_path="$2"
    local owner
    local candidate
    local owner_lines

    case "$family" in
        deb)
            owner=""
            for candidate in "$source_path" "${source_path#/usr}"; do
                [ -n "$candidate" ] || continue
                owner_lines="$(dpkg-query -S "$candidate" 2>/dev/null || true)"
                if [ -n "$owner_lines" ]; then
                    owner="$(printf '%s\n' "$owner_lines" | sed -n '1s/: \/.*//p')"
                    break
                fi
            done
            ;;
        rpm)
            owner="$(rpm -qf --queryformat '%{NAME}' "$source_path" 2>/dev/null || true)"
            ;;
        *)
            fic_gui_runtime_error "unsupported package family '$family'"
            return 1
            ;;
    esac

    [ -n "$owner" ] || return 1
    printf '%s\n' "$owner"
}

fic_gui_classify_runtime_dependency() {
    local family="$1"
    local source_path="$2"
    local library_name

    library_name="$(basename "$source_path")"
    case "$library_name" in
        libQt6*.so*)
            printf 'bundle\n'
            return 0
            ;;
    esac

    if fic_gui_package_owner "$family" "$(readlink -f "$source_path")" >/dev/null; then
        printf 'system\n'
        return 0
    fi

    printf 'reject\n'
}

fic_gui_record_payload_path() {
    local mapping_file="$1"
    local package_root="$2"
    local installed_path="$3"
    local source_path="$4"
    local kind="$5"

    printf '%s\t%s\t%s\n' \
        "${installed_path#$package_root}" \
        "$(readlink -f "$source_path")" \
        "$kind" >> "$mapping_file"
}

fic_gui_copy_shared_library() {
    local source_path="$1"
    local package_root="$2"
    local destination_dir="$3"
    local mapping_file="$4"
    local real_source
    local source_base
    local real_base
    local soname
    local destination_path

    [ -e "$source_path" ] || return 0
    mkdir -p "$destination_dir"

    real_source="$(readlink -f "$source_path")"
    source_base="$(basename "$source_path")"
    real_base="$(basename "$real_source")"

    destination_path="$destination_dir/$real_base"
    install -m 0644 "$real_source" "$destination_path"
    fic_gui_record_payload_path \
        "$mapping_file" "$package_root" "$destination_path" "$real_source" library

    if [ "$source_base" != "$real_base" ] && [ ! -e "$destination_dir/$source_base" ]; then
        ln -s "$real_base" "$destination_dir/$source_base"
        fic_gui_record_payload_path \
            "$mapping_file" "$package_root" "$destination_dir/$source_base" "$real_source" library
    fi

    soname="$(objdump -p "$real_source" 2>/dev/null | awk '/SONAME/ { print $2; exit }')"
    if [ -n "$soname" ] && [ "$soname" != "$real_base" ] && [ ! -e "$destination_dir/$soname" ]; then
        ln -s "$real_base" "$destination_dir/$soname"
        fic_gui_record_payload_path \
            "$mapping_file" "$package_root" "$destination_dir/$soname" "$real_source" library
    fi
}

fic_gui_collect_qt_runtime_closure() {
    local family="$1"
    local output_file="$2"
    shift 2
    local pending=("$@")
    local seen_file
    local current
    local dep_path
    local classification

    seen_file="$(mktemp "$STAGING_BASE/gui-runtime-seen-XXXXXX")"
    : > "$seen_file"
    : > "$output_file"

    while [ "${#pending[@]}" -gt 0 ]; do
        current="${pending[0]}"
        pending=("${pending[@]:1}")
        [ -n "$current" ] && [ -e "$current" ] || continue
        current="$(readlink -f "$current")"
        grep -Fxq "$current" "$seen_file" && continue
        printf '%s\n' "$current" >> "$seen_file"

        if ldd "$current" 2>&1 | grep -q '=> not found'; then
            ldd "$current" >&2 || true
            rm -f "$seen_file"
            fic_gui_runtime_error "unresolved ELF dependency while inspecting $current"
            return 1
        fi

        while IFS= read -r dep_path; do
            [ -n "$dep_path" ] || continue
            dep_path="$(readlink -f "$dep_path")"
            classification="$(fic_gui_classify_runtime_dependency "$family" "$dep_path")"
            case "$classification" in
                bundle)
                    if ! fic_gui_package_owner "$family" "$dep_path" >/dev/null; then
                        rm -f "$seen_file"
                        fic_gui_runtime_error "Qt dependency has no package owner: $dep_path"
                        return 1
                    fi
                    if ! grep -Fxq "$dep_path" "$output_file"; then
                        printf '%s\n' "$dep_path" >> "$output_file"
                        pending+=("$dep_path")
                    fi
                    ;;
                system)
                    ;;
                reject|*)
                    rm -f "$seen_file"
                    fic_gui_runtime_error "unexpected unowned runtime dependency: $dep_path"
                    return 1
                    ;;
            esac
        done < <(ldd "$current" 2>/dev/null | awk '
            /=> \// { print $3; next }
            /^[[:space:]]*\// { print $1 }
        ')
    done

    rm -f "$seen_file"
}

fic_gui_install_required_plugin() {
    local package_root="$1"
    local qt_plugin_dir="$2"
    local relative_path="$3"
    local mapping_file="$4"
    local source_path="$qt_plugin_dir/$relative_path"
    local destination_path="$package_root${GUI_QT_BUNDLE_ROOT}/plugins/$relative_path"

    if [ ! -f "$source_path" ]; then
        fic_gui_runtime_error "required Qt plugin is missing: $source_path"
        return 1
    fi
    mkdir -p "$(dirname "$destination_path")"
    install -m 0755 "$source_path" "$destination_path"
    fic_gui_record_payload_path \
        "$mapping_file" "$package_root" "$destination_path" "$source_path" plugin
    printf '%s\n' "$source_path"
}

fic_gui_create_launcher() {
    local package_root="$1"

    cat > "$package_root/opt/fic/bin/fic-gui" <<'EOF'
#!/bin/sh
set -e

SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$SCRIPT_PATH")" && pwd)"
FIC_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"

if [ "${FIC_QT_ROOT+x}" = x ]; then
    if [ -z "$FIC_QT_ROOT" ]; then
        echo "FIC_QT_ROOT must not be empty when it is set" >&2
        exit 2
    fi
    QT_RUNTIME_ROOT="$FIC_QT_ROOT"
else
    QT_RUNTIME_ROOT="$FIC_ROOT/qt"
fi

export LD_LIBRARY_PATH="$QT_RUNTIME_ROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export QT_PLUGIN_PATH="$QT_RUNTIME_ROOT/plugins"
export QT_QPA_PLATFORM_PLUGIN_PATH="$QT_RUNTIME_ROOT/plugins/platforms"

exec "$SCRIPT_DIR/fic-gui.real" "$@"
EOF

    chmod 0755 "$package_root/opt/fic/bin/fic-gui"
}

fic_gui_create_qt_conf() {
    local package_root="$1"

    cat > "$package_root/opt/fic/bin/qt.conf" <<'EOF'
[Paths]
Prefix = ../qt
Plugins = plugins
Libraries = lib
EOF

    chmod 0644 "$package_root/opt/fic/bin/qt.conf"
}

fic_gui_bundle_qt_runtime() {
    local package_root="$1"
    local family="$2"
    local qt_plugin_dir="$3"
    local mapping_file
    local runtime_list
    local plugin_roots=()
    local plugin_source
    local qt_library

    mapping_file="$(mktemp "$STAGING_BASE/gui-runtime-map-XXXXXX")"
    runtime_list="$(mktemp "$STAGING_BASE/gui-runtime-list-XXXXXX")"
    : > "$mapping_file"

    mkdir -p \
        "$package_root${GUI_QT_BUNDLE_ROOT}/lib" \
        "$package_root${GUI_QT_BUNDLE_ROOT}/plugins"

    for plugin_source in platforms/libqxcb.so imageformats/libqjpeg.so; do
        plugin_source="$(fic_gui_install_required_plugin \
            "$package_root" "$qt_plugin_dir" "$plugin_source" "$mapping_file")" || return 1
        plugin_roots+=("$plugin_source")
    done

    fic_gui_collect_qt_runtime_closure \
        "$family" "$runtime_list" "$FIC_GUI_BUILD_DIR/fic-gui" "${plugin_roots[@]}" || return 1

    while IFS= read -r qt_library; do
        [ -n "$qt_library" ] || continue
        fic_gui_copy_shared_library \
            "$qt_library" "$package_root" \
            "$package_root${GUI_QT_BUNDLE_ROOT}/lib" "$mapping_file" || return 1
    done < "$runtime_list"

    python3 "$ROOT_DIR/packaging/lib/gui-runtime-manifest.py" generate \
        --family "$family" \
        --package-root "$package_root" \
        --mapping "$mapping_file" \
        --project-license "$ROOT_DIR/LICENSE" || return 1

    rm -f "$mapping_file" "$runtime_list"
}

fic_gui_verify_runtime_compliance() {
    local package_root="$1"
    local binary="$package_root/opt/fic/bin/fic-gui.real"

    if ! readelf -d "$binary" | grep -Eq 'Shared library: \[libQt6[^]]+\.so'; then
        fic_gui_runtime_error "$binary has no dynamic Qt DT_NEEDED entry"
        return 1
    fi

    python3 "$ROOT_DIR/packaging/lib/gui-runtime-manifest.py" verify \
        --package-root "$package_root"

    "$package_root/opt/fic/bin/fic-gui" --version >/dev/null

    local license_output
    license_output="$("$package_root/opt/fic/bin/fic-gui" --license-info)" || return 1
    printf '%s\n' "$license_output" | grep -Fq 'Sustainable Use License 1.0' || {
        fic_gui_runtime_error "fic-gui --license-info omits the FIC license"
        return 1
    }
    printf '%s\n' "$license_output" | grep -Fq '/usr/share/doc/fic-gui/' || {
        fic_gui_runtime_error "fic-gui --license-info omits the package documentation path"
        return 1
    }

    fic_gui_verify_gui_smoke "$package_root"
}

fic_gui_assert_smoke_output() {
    local output="$1"
    local qt_root="$2"
    local qt_library

    grep -Fq 'qpa-platform=xcb' <<<"$output" || {
        fic_gui_runtime_error "GUI smoke test did not load the XCB QPA plugin"
        return 1
    }
    grep -Fq 'jpeg-plugin=ok' <<<"$output" || {
        fic_gui_runtime_error "GUI smoke test did not decode the JPEG fixture"
        return 1
    }
    printf '%s\n' "$output" | grep -F "qt-core-path=$qt_root/lib/" >/dev/null || {
        fic_gui_runtime_error "GUI smoke test loaded Qt Core outside $qt_root"
        return 1
    }
    printf '%s\n' "$output" | grep -F "$qt_root/plugins/platforms/libqxcb.so" >/dev/null || {
        fic_gui_runtime_error "GUI smoke test did not load bundled libqxcb.so"
        return 1
    }
    printf '%s\n' "$output" | grep -F "$qt_root/plugins/imageformats/libqjpeg.so" >/dev/null || {
        fic_gui_runtime_error "GUI smoke test did not load bundled libqjpeg.so"
        return 1
    }
    for qt_library in Core Gui Widgets; do
        printf '%s\n' "$output" |
            grep -E "calling init: ${qt_root}/lib/libQt6${qt_library}\\.so" >/dev/null || {
            fic_gui_runtime_error \
                "GUI smoke test did not load Qt ${qt_library} from $qt_root"
            return 1
        }
    done
    if printf '%s\n' "$output" |
        grep -E 'calling init: .*libQt6[^/]*\.so' |
        grep -Fv "calling init: $qt_root/lib/" >/dev/null; then
        fic_gui_runtime_error "GUI smoke test loaded a Qt library outside $qt_root"
        return 1
    fi
}

fic_gui_verify_gui_smoke() {
    local package_root="$1"
    local launcher="$package_root/opt/fic/bin/fic-gui"
    local bundled_root="$package_root${GUI_QT_BUNDLE_ROOT}"
    local override_root
    local smoke_output

    command -v xvfb-run >/dev/null 2>&1 || {
        fic_gui_runtime_error "xvfb-run is required for the packaged GUI smoke test"
        return 1
    }

    smoke_output="$(LD_DEBUG=libs QT_DEBUG_PLUGINS=1 \
        xvfb-run -a "$launcher" --gui-smoke-test 2>&1)" || {
        printf '%s\n' "$smoke_output" >&2
        fic_gui_runtime_error "bundled Qt GUI smoke test failed"
        return 1
    }
    fic_gui_assert_smoke_output "$smoke_output" "$bundled_root" || return 1

    override_root="$(mktemp -d "$STAGING_BASE/gui-qt-override-XXXXXX")"
    cp -a "$bundled_root/." "$override_root/"
    smoke_output="$(FIC_QT_ROOT="$override_root" LD_DEBUG=libs QT_DEBUG_PLUGINS=1 \
        xvfb-run -a "$launcher" --gui-smoke-test 2>&1)" || {
        printf '%s\n' "$smoke_output" >&2
        rm -rf "$override_root"
        fic_gui_runtime_error "FIC_QT_ROOT GUI smoke test failed"
        return 1
    }
    fic_gui_assert_smoke_output "$smoke_output" "$override_root" || {
        rm -rf "$override_root"
        return 1
    }
    rm -rf "$override_root"
}
