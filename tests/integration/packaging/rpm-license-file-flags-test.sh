#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:?repository root is required}"
[ "${FIC_DISPOSABLE_RPM_TEST:-}" = "1" ] || {
    echo "rpm-license-file-flags-test must run in a disposable RPM container" >&2
    exit 2
}

TEMP_DIR="$(mktemp -d /tmp/fic-rpm-license-flags-XXXXXX)"
trap 'rm -rf "$TEMP_DIR"' EXIT
TOPDIR="$TEMP_DIR/rpmbuild"
mkdir -p "$TOPDIR"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

printf 'MIT fixture\n' > "$TOPDIR/SOURCES/MIT.txt"
printf 'BSD fixture\n' > "$TOPDIR/SOURCES/BSD-3-Clause.txt"
printf 'ordinary documentation\n' > "$TOPDIR/SOURCES/README"

cat > "$TOPDIR/SPECS/rpm-license-flags-fixture.spec" <<'EOF'
Name: rpm-license-flags-fixture
Version: 1
Release: 1
Summary: RPM file-flags fixture
License: MIT AND BSD-3-Clause
Group: Development/Other
BuildArch: noarch
Source0: MIT.txt
Source1: BSD-3-Clause.txt
Source2: README

%description
RPM file-flags fixture.

%prep
:

%build
:

%install
mkdir -p %buildroot/usr/share/licenses/test %buildroot/usr/share/doc/test
install -m 0644 %{SOURCE0} %buildroot/usr/share/licenses/test/MIT.txt
install -m 0644 %{SOURCE1} %buildroot/usr/share/licenses/test/BSD-3-Clause.txt
install -m 0644 %{SOURCE2} %buildroot/usr/share/doc/test/README

%files
%license /usr/share/licenses/test/MIT.txt
%license /usr/share/licenses/test/BSD-3-Clause.txt
%doc /usr/share/doc/test/README
EOF

rpmbuild --define "_topdir $TOPDIR" --define "_allow_root_build 1" \
    -bb "$TOPDIR/SPECS/rpm-license-flags-fixture.spec" >/dev/null
fixture_rpm="$(find "$TOPDIR/RPMS" -type f -name 'rpm-license-flags-fixture-*.rpm' | head -n 1)"
[ -n "$fixture_rpm" ] || {
    echo "RPM license fixture was not built" >&2
    exit 1
}
rpm -i "$fixture_rpm"

notices="$(python3 - "$ROOT_DIR" <<'PY'
import importlib.util
from pathlib import Path
import sys

module_path = Path(sys.argv[1]) / "packaging/lib/gui-runtime-manifest.py"
spec = importlib.util.spec_from_file_location("gui_runtime_manifest", module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for path in module.rpm_license_notice_paths(
    "rpm-license-flags-fixture-1-1.src.rpm",
    "rpm-license-flags-fixture",
    ["rpm-license-flags-fixture"],
):
    print(path)
PY
)"

grep -Fxq '/usr/share/licenses/test/MIT.txt' <<<"$notices"
grep -Fxq '/usr/share/licenses/test/BSD-3-Clause.txt' <<<"$notices"
if grep -Fq '/usr/share/doc/test/README' <<<"$notices"; then
    echo "ordinary %doc file was treated as a license notice" >&2
    exit 1
fi

rm -f /usr/share/licenses/test/BSD-3-Clause.txt
if python3 - "$ROOT_DIR" >/dev/null 2>&1 <<'PY'
import importlib.util
from pathlib import Path
import sys

module_path = Path(sys.argv[1]) / "packaging/lib/gui-runtime-manifest.py"
spec = importlib.util.spec_from_file_location("gui_runtime_manifest", module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.rpm_license_notice_paths(
    "rpm-license-flags-fixture-1-1.src.rpm",
    "rpm-license-flags-fixture",
    ["rpm-license-flags-fixture"],
)
PY
then
    echo "missing RPM-declared %license file was accepted" >&2
    exit 1
fi

printf 'mixed MIT fixture\n' > "$TOPDIR/SOURCES/Mixed-MIT.txt"
printf 'mixed BSD fixture\n' > "$TOPDIR/SOURCES/Mixed-BSD-3-Clause.txt"
printf 'mixed Apache fixture\n' > "$TOPDIR/SOURCES/Mixed-Apache-2.0.txt"
printf 'excluded documentation\n' > "$TOPDIR/SOURCES/Mixed-README"

cat > "$TOPDIR/SPECS/qt6-base.spec" <<'EOF'
Name: qt6-base
Version: 1.0
Release: 1
Summary: Mixed RPM notice layout fixture
License: MIT AND BSD-3-Clause AND Apache-2.0
Group: Development/Other
BuildArch: noarch
Source0: Mixed-MIT.txt
Source1: Mixed-BSD-3-Clause.txt
Source2: Mixed-Apache-2.0.txt
Source3: Mixed-README

%description
Source package for the mixed RPM notice layout fixture.

%package -n qt6-base-license-fixture
Summary: Declared license part of the mixed layout fixture
Group: Development/Other

%description -n qt6-base-license-fixture
Declared license part of the mixed layout fixture.

%package -n qt6-base-common
Summary: ALT-style documentation part of the mixed layout fixture
Group: Development/Other

%description -n qt6-base-common
ALT-style documentation part of the mixed layout fixture.

%prep
:

%build
:

%install
mkdir -p %buildroot/usr/share/licenses/example
mkdir -p %buildroot/usr/share/doc/qt6-base-common-1.0
mkdir -p %buildroot/usr/share/doc/qt6-base-common
install -m 0644 %{SOURCE0} %buildroot/usr/share/licenses/example/MIT.txt
install -m 0644 %{SOURCE1} %buildroot/usr/share/doc/qt6-base-common-1.0/BSD-3-Clause.txt
install -m 0644 %{SOURCE2} %buildroot/usr/share/doc/qt6-base-common-1.0/Apache-2.0.txt
install -m 0644 %{SOURCE3} %buildroot/usr/share/doc/qt6-base-common/README

%files -n qt6-base-license-fixture
%license /usr/share/licenses/example/MIT.txt

%files -n qt6-base-common
%doc /usr/share/doc/qt6-base-common-1.0/BSD-3-Clause.txt
%doc /usr/share/doc/qt6-base-common-1.0/Apache-2.0.txt
%doc /usr/share/doc/qt6-base-common/README
EOF

rpmbuild --define "_topdir $TOPDIR" --define "_allow_root_build 1" \
    -bb "$TOPDIR/SPECS/qt6-base.spec" >/dev/null
mixed_license_rpm="$(find "$TOPDIR/RPMS" -type f -name 'qt6-base-license-fixture-*.rpm' | head -n 1)"
mixed_common_rpm="$(find "$TOPDIR/RPMS" -type f -name 'qt6-base-common-*.rpm' | head -n 1)"
[ -n "$mixed_license_rpm" ] && [ -n "$mixed_common_rpm" ] || {
    echo "mixed RPM notice fixture was not built" >&2
    exit 1
}
rpm -i "$mixed_license_rpm" "$mixed_common_rpm"

mixed_notices() {
    python3 - "$ROOT_DIR" <<'PY'
import importlib.util
from pathlib import Path
import sys

module_path = Path(sys.argv[1]) / "packaging/lib/gui-runtime-manifest.py"
spec = importlib.util.spec_from_file_location("gui_runtime_manifest", module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for path in module.rpm_license_notice_paths(
    "qt6-base-1.0-1.src.rpm",
    "qt6-base",
    ["qt6-base-common", "qt6-base-license-fixture"],
):
    print(path)
PY
}

expected_notices="$(printf '%s\n' \
    /usr/share/doc/qt6-base-common-1.0/Apache-2.0.txt \
    /usr/share/doc/qt6-base-common-1.0/BSD-3-Clause.txt \
    /usr/share/licenses/example/MIT.txt)"
[ "$(mixed_notices)" = "$expected_notices" ] || {
    echo "mixed RPM notice layout did not produce the deterministic union" >&2
    mixed_notices >&2
    exit 1
}

restore_mixed_fixture() {
    rpm -i --replacepkgs "$mixed_license_rpm" "$mixed_common_rpm" >/dev/null
}

rm -f /usr/share/licenses/example/MIT.txt
if mixed_notices >/dev/null 2>&1; then
    echo "missing mixed-layout %license file was accepted" >&2
    exit 1
fi
restore_mixed_fixture

rm -f /usr/share/doc/qt6-base-common-1.0/BSD-3-Clause.txt
if mixed_notices >/dev/null 2>&1; then
    echo "missing ALT fallback corpus file was accepted" >&2
    exit 1
fi
restore_mixed_fixture

rm -f /usr/share/doc/qt6-base-common-1.0/Apache-2.0.txt
ln -s /usr/share/doc/qt6-base-common-1.0/BSD-3-Clause.txt \
    /usr/share/doc/qt6-base-common-1.0/Apache-2.0.txt
if mixed_notices >/dev/null 2>&1; then
    echo "symlink in ALT fallback corpus was accepted" >&2
    exit 1
fi
