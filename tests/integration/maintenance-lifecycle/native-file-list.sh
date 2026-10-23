#!/bin/sh
# MUST run in a disposable container: installs a dummy fic-cli package, not FIC.
set -eu
[ "${FIC_MAINTENANCE_NATIVE:-}" = 1 ] || exit 77
[ -f /.dockerenv ] || { echo 'disposable Docker fixture required' >&2; exit 77; }
src=${1:-/src}
sh "$src/tests/integration/maintenance-lifecycle/build-database-native.sh" "$src"
fixture=$(mktemp -d /var/tmp/fic-filelist-XXXXXX)
trap 'rm -rf "$fixture"' EXIT
if command -v dpkg-deb >/dev/null 2>&1; then
    ! dpkg-query -s fic-cli >/dev/null 2>&1 || { echo 'refuse existing fic-cli' >&2; exit 1; }
    tree="$fixture/tree"
    mkdir -p "$tree/DEBIAN" "$tree/usr/share/fic-m1-filelist"
    printf 'Package: fic-cli\nVersion: 1\nArchitecture: all\nMaintainer: FIC test\nDescription: dummy file list only\n' > "$tree/DEBIAN/control"
    printf 'fixture\n' > "$tree/usr/share/fic-m1-filelist/file with spaces"
    ln -s 'file with spaces' "$tree/usr/share/fic-m1-filelist/link"
    dpkg-deb --build "$tree" "$fixture/fixture.deb"
    dpkg -i "$fixture/fixture.deb"
    manager=dpkg
else
    ! rpm -q fic-cli >/dev/null 2>&1 || { echo 'refuse existing fic-cli' >&2; exit 1; }
    mkdir -p "$fixture/rpm/BUILD" "$fixture/rpm/RPMS" "$fixture/rpm/SOURCES" "$fixture/rpm/SPECS" "$fixture/rpm/SRPMS"
    cat > "$fixture/rpm/SPECS/fixture.spec" <<'SPEC'
Name: fic-cli
Version: 1
Release: alt1
Summary: Dummy file list only
License: MIT
BuildArch: noarch
Group: Development/Other
AutoReqProv: no
%description
Isolated file list fixture; no FIC implementation or security hooks.
%install
mkdir -p %{buildroot}/usr/share/fic-m1-filelist
printf 'fixture\n' > '%{buildroot}/usr/share/fic-m1-filelist/file with spaces'
ln -s 'file with spaces' %{buildroot}/usr/share/fic-m1-filelist/link
%files
%dir /usr/share/fic-m1-filelist
"/usr/share/fic-m1-filelist/file with spaces"
/usr/share/fic-m1-filelist/link
SPEC
    # ALT deliberately forbids root rpmbuild; use a private fixture builder.
    useradd --system --no-create-home m1-filelist-build
    chmod 0755 "$fixture"
    chown -R m1-filelist-build "$fixture/rpm"
    runuser -u m1-filelist-build -- rpmbuild --define "_topdir $fixture/rpm" -bb "$fixture/rpm/SPECS/fixture.spec"
    rpm -ivh "$fixture/rpm/RPMS/noarch/fic-cli-1-alt1.noarch.rpm"
    manager=rpm
fi
/usr/local/bin/m1-package-db "$manager" fic-cli > "$fixture/proof"
cat "$fixture/proof"
# The C++ query owns actual transaction locks, repeats proof and refuses unknown
# package names. Assert both non-directory payload objects, including spaces.
python3 - "$fixture/proof" <<'PY'
import pathlib,sys
lines=pathlib.Path(sys.argv[1]).read_text().splitlines()
assert 'OWNED\t/usr/share/fic-m1-filelist/file with spaces' in lines
assert 'OWNED\t/usr/share/fic-m1-filelist/link' in lines
assert 'OWNED_REPEAT_AND_UNKNOWN_REFUSAL_PASS' in lines
print('PASS: real native file list under manager locks, repeated query, known package restriction')
PY
