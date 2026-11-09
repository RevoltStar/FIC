# Private client permissions regression

Base: `68b546ad` (`main`); regression identified in
`752354c86f623cc0599e7a274b0452516ebd254b`. Date: 2026-11-09.
The recursive permission removal in that lifecycle refactor remains in place.

## Production change

* `packaging/deb/build-fic-debian12-deb.sh`: existing client postinst generator
  now accepts only fic-cli/fic-gui and fixes only the owning client's exact
  payload paths and `/opt/fic`, `/opt/fic/bin`. It runs for every configure,
  including independent reinstall/update, without requiring fic.postinst again.
  Abort actions perform no metadata repair. All paths are validated before any
  chown/chmod: physical root-owned non-writable parents; root-owned, non-writable,
  single-link regular files. Symlinks, wrong object types/owners, hardlinks and
  unsafe writable paths cause failure, not permission repair of foreign state.
* `packaging/rpm/build-fic-alt-p11-rpm.sh`: generated file lists declare the
  three files with `%attr(0750,root,fic)` and shared bin directory with
  `%dir %attr(2750,root,fic)`. The common producer applies that same directory
  entry to every package staging it, preventing mismatched shared-directory
  attributes. `%defattr(-,root,root,-)` remains for other payload paths.
  No client permission scriptlet is added. Existing exclusions of `/opt/fic`
  and `/opt/fic/config` are preserved.

Post-install/reinstall/update facts:

| Path | Owner/group | Mode |
|---|---|---|
| `/opt` | root:root in the native fixture; unchanged | 0755 |
| `/opt/fic` | root:fic | 2750 |
| `/opt/fic/bin` | root:fic | 2750 |
| `/opt/fic/bin/fic-cli` | root:fic | 0750 |
| `/opt/fic/bin/fic-gui` | root:fic | 0750 |
| `/opt/fic/bin/fic-gui.real` | root:fic | 0750 |

DEB **archive** IDs deliberately remain root:root with mode0750 because
`--root-owner-group` is retained; each client's native configure establishes
root:fic. RPM archive metadata already declares root:fic and is independently
queried before install. RPM private root initialization remains the main FIC
lifecycle contract; the client gate seeds that already-established root.

No lifecycle-state, daemon startup, policy apply/rollback, journal/ownership,
administrative socket authorization or uninstall-overload algorithm changed.
There is no recursive filesystem operation or new general permissions service.

## Native evidence and limitations

| Distro | Native manager | Archive metadata | Install/reinstall/upgrade | CLI + GUI as fic member | Outsider EACCES / persistent metadata |
|---|---|---|---|---|---|
| Debian12 | dpkg | PASS | PASS | PASS | PASS |
| Debian13 | dpkg | PASS | PASS | PASS | PASS |
| Ubuntu24.04 | dpkg | PASS | PASS | PASS | PASS |
| Ubuntu26.04 | dpkg | PASS | PASS | PASS | PASS |
| ALT p11 | RPM | PASS | PASS | PASS | PASS |

The existing package-lifecycle harness is extended with a focused Podman runner.
Real native FIC ELF payloads/bundled Qt from cached distribution packages are
repackaged with current **production** postinst/file-list/spec/archive helpers.
No shell mock stands in for a FIC client. Package fixture versions0.1.1→0.1.2
exercise native upgrade; they are not release builds or a product version bump.
Input archive/ELF hashes are recorded in build.log; compact evidence records
source hashes, image IDs, native manager/OS facts, package hashes, UID/group
facts and actual invocation/metadata results.

This deliberately bypasses dependency admission (`dpkg --force-depends`,
`rpm --nodeps`) to test client packages independently of daemon package admission.
It is **not** a complete clean-system FIC install, current-HEAD ELF rebuild,
daemon/IPC/policy test, or full release DEB/RPM build. Main fic postinst is never
rerun to repair client permissions. No full-stack install result is claimed.

The gate:

* Validates real `/etc/os-release`, manager version and every native archive's
  client metadata. Checks each client's installed metadata immediately after
  its own install/reinstall/update, before a second client can hide a defect.
* Creates real unprivileged ficmember/ficoutsider users. Runs CLI --version under
  ficmember, not root. Both GUI launcher and real ELF run `--gui-smoke-test`
  through Xvfb with xcb, JPEG decoding, a real shown QWidget and the Qt event
  loop; each success must report a loaded `/opt/fic/qt/` library. This is a
  graphical launch proof, not test-x or a full administrative GUI interaction.
* Under the actual outsider UID, attempts exec of each path and requires kernel
  `PermissionError(EACCES)`; a program-level IPC rejection is not accepted.
  The member cannot write clients or bin. Modes grant fic no write permission.
* Snapshots owner/group/mode/inode/mtime/ctime/content of persistent fixture
  directories/files under config/db/log/notify, including named config, device
  DB, journal/witness and incident-state sentinels. Compares after every package
  operation. These are metadata fixtures; no live daemon journal is fabricated
  or admitted. Preserved metadata is checked against actual stat results.
* On DEB, executes generated postinst against symlink, hardlink, directory,
  symlink-parent, writable-parent/payload and non-root-owner cases; requires
  refusal and preserved foreign/persistent metadata. Abort-upgrade is a no-op.

Ubuntu24.04's root dist GUI predates the smoke flag and timed out; its real
newer cached native package from dist/pam-activation/ubuntu2404 was used instead,
with input hashes retained. Initial GUI probes exposed missing test-image
libraries; the native Qt dependency closure was installed only in images.
The successful tests still prove private bundled Qt, not system Qt substitution.

Local Docker socket and old build-host SSH access were unavailable. Tests used
rootless Podman with no network in native runs, no privileged flag and no host
security mounts. Only source/input artifacts read-only and ignored output dirs
writable were mounted. Runtime image preparation alone used network. ALT
registry timed out; official Docker Hub `alt:p11` was verified as
ID=altlinux,VERSION_ID=11,ALT_BRANCH_ID=p11. HTTPS mirror access retained CA
verification using a public CA bundle; no TLS verification was disabled.

## Reproduce

Runtime recipes are `Dockerfile.client-access-deb` and
`Dockerfile.client-access-alt` in tests/integration/package-lifecycle. The DEB
recipe accepts BASE=debian:12,debian:13,ubuntu:24.04,ubuntu:26.04. For ALT supply
public system CA bundle as ca.crt in an otherwise temporary build context.

```bash
podman build --build-arg BASE=docker.io/library/debian:12 \
  -f tests/integration/package-lifecycle/Dockerfile.client-access-deb \
  -t localhost/fic-client-access:debian12 /tmp/empty-build-context
bash tests/integration/package-lifecycle/run-client-access.sh \
  localhost/fic-client-access:debian12 deb dist debian12
# Same runner/image tags: debian13,ubuntu2604; Ubuntu24.04 uses:
bash tests/integration/package-lifecycle/run-client-access.sh \
  localhost/fic-client-access:ubuntu2404 deb dist/pam-activation/ubuntu2404 ubuntu2404
bash tests/integration/package-lifecycle/run-client-access.sh \
  localhost/fic-client-access:altp11 rpm dist altp11
```

Runner output and receipts:
`build-package-lifecycle/client-access-<row>/{build.log,native.log,packages/,results/}`.
Final native-only rerun reused the unchanged built packages via the runner's
second `podman run` command; it added named metadata fixtures and did not relabel
old results as current. Compact tracked evidence:
[private-client-permissions.json](../tests/integration/package-lifecycle/evidence/private-client-permissions.json).

Configure + affected CTest:8/8 PASS (five labelled static), including new
private_client_permissions_tests, DEB dependency analysis, Qt bundle compliance,
PAM/prelogin/desktop/notification packaging and build-resource checks. Bash
syntax, Python compilation and git diff --check PASS. Logs:
/tmp/fic-client-{configure,ctest,deb-depends,gui-compliance,pam-static}.log.
Full C++ build/CTest and installed session-agent layout were not repeated:
production executable/library sources and install layout are unchanged.

Additional changed paths: packaging/deb/README.md, packaging/rpm/README.md,
tests/CMakeLists.txt, tests/integration/packaging/private-client-permissions-test.sh,
tests/integration/package-lifecycle/{build-client-access.sh,client_access_native.py,
run-client-access.sh,Dockerfile.client-access-deb,Dockerfile.client-access-alt},
the compact evidence above, this report and docs/HANDOFF.md.
