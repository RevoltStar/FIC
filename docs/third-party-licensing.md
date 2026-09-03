# Third-party licensing for fic-gui binary packages

## License boundary

FIC source code remains licensed under the Sustainable Use License Version 1.0
(`SUL-1.0`) in the repository root `LICENSE`. Qt and other third-party files do
not become covered by SUL-1.0 merely because a `fic-gui` package contains them.
They retain their own licenses and notices.

The supported Linux package builders use shared Qt 6 libraries. They reject a
`fic-gui.real` without a Qt `DT_NEEDED` entry. Qt describes LGPLv3 as an option
for applications that can meet its terms and notes that some Qt modules are
GPL-only; see the official
[Qt licensing overview](https://doc.qt.io/qt-6/licensing.html). Qt also states
that dynamic linking and the ability to install and run a modified library are
relevant LGPL obligations; see its
[open-source obligations summary](https://www.qt.io/development/open-source-lgpl-obligations).
These links explain the design but are not a substitute for the license texts
or Corresponding Source delivered for a release.

## Runtime composition and replacement

The DEB and RPM builders share `packaging/lib/gui-runtime-compliance.sh`. The
closure starts with:

- `/opt/fic/bin/fic-gui.real`;
- the X11 QPA plugin `platforms/libqxcb.so`;
- the JPEG plugin `imageformats/libqjpeg.so`, required by the packaged GUI
  resource.

`ldd` is used recursively to resolve their ELF dependencies. Only required
`libQt6*.so*` libraries owned by the distribution's `qt6-base` source package
are copied. Package-owned non-Qt libraries remain system dependencies. An
unresolved or non-package-owned dependency is rejected. This allow/system/reject
policy prevents a broad `libQt6*.so*` copy and prevents arbitrary host libraries
from silently entering `/opt/fic/qt`.

The normal launcher selects `/opt/fic/qt`. A compatible modified Qt can be used
with:

```bash
FIC_QT_ROOT=/path/to/custom/qt /opt/fic/bin/fic-gui
```

The selected root must contain `lib/` and `plugins/`. The launcher places only
that root in the Qt-specific environment variables. Advanced users may execute
`fic-gui.real` directly with system or manually configured Qt paths.

## Installed compliance payload

Every `fic-gui` binary package installs:

- `/usr/share/doc/fic-gui/licenses/FIC-SUL-1.0.txt`;
- `/usr/share/doc/fic-gui/licenses/LGPL-3.0-only.txt` and
  `GPL-3.0-only.txt` (LGPLv3 incorporates GPLv3 terms);
- distribution copyright/license files covering the packages supplying the
  bundled Qt files (identical notices are stored once);
- `/usr/share/doc/fic-gui/third-party-components.json`;
- `/usr/share/doc/fic-gui/SOURCE_OFFER.md`.

The deterministic JSON manifest is sorted by installed path. Each library,
SONAME link and plugin records its installed/source paths, kind, binary package,
binary version, distribution-declared license, source package and exact source
version, notice path, and SHA-256. Generation fails if a component cannot be
attributed to the allowed Qt source package. The package compliance check fails
if the manifest and actual `/opt/fic/qt` payload differ.

The distro copyright/license file is authoritative for the particular build.
Maintainers must review it when the Qt package version changes; they must not
assume all Qt modules or embedded third-party code have the same license. The
current closure is deliberately restricted to Qt Base and excludes GPL-only Qt
add-on modules.

## Corresponding Source release contract

`SOURCE_OFFER.md` records the exact source package identities found during the
package build and gives distro-specific retrieval guidance. A generic upstream
Qt URL alone is not treated as Corresponding Source for downstream package
builds and patches.

Before running an official non-verify release build, the maintainer must prepare
a retained artifact directory and set `FIC_CORRESPONDING_SOURCE_DIR`. It must
contain `corresponding-source.json` with this shape:

```json
{
  "schema_version": 1,
  "sources": [{
    "source_package": "qt6-base",
    "source_version": "exact distro source version",
    "artifacts": [{
      "file": "relative/path/to/source-artifact",
      "sha256": "64 lowercase hexadecimal characters"
    }]
  }]
}
```

Each referenced file must be inside that directory and match its SHA-256. After
all platform packages are built, `packaging/release/build-release.sh` compares
their generated manifests with the index. Missing source identities, files, or
hashes stop publication. On success, both the source set and per-platform
third-party manifests are copied into the release output.

For Debian-family platforms, obtain the exact recorded version from the matching
snapshot or release repository with `apt-get source
SOURCE_PACKAGE=SOURCE_VERSION` and retain all `.dsc`, upstream tarballs and
Debian patch archives. For ALT p11, retain the exact source RPM named by the RPM
metadata. If those exact artifacts cannot be obtained and controlled by the
publisher, public binary release is blocked rather than declared compliant.

This workflow is an engineering compliance control, not legal advice. Release
maintainers remain responsible for reviewing the actual notices and applicable
license obligations for every published build.
