# Current workspace

## Current base / task
* `main`; task base `68b546ad` (PAM I6 evidence follow-up).
* Private fic-cli/fic-gui permissions regression from `752354c8` fixed. Single user-authorized completion commit; no push.

## Accepted architecture / invariants
* Private clients fic-cli, fic-gui, fic-gui.real: root:fic0750. Private root/bin: root:fic2750, group cannot write. Outsiders cannot execute clients.
* DEB --root-owner-group retained; each client's configure postinst independently fixes exact own files + two parents, validates complete path set before mutation (physical/root-owned/non-writable dirs and single-link regular root-owned/non-writable files). Abort actions no-op; unsafe objects fail closed.
* RPM native attrs for three files and identical %dir attrs for shared bin in all generated owners; no chown scriptlet. Existing root/config exclusions retained.
* No recursive metadata repair or changes to persistent state, package lifecycle/admission, rollback/journal, IPC auth or uninstall overload. Native tests ONLY disposable rootless Podman, no host security mounts/apply.

## Completed / changed areas
* Two production builders + ownership sections of DEB/RPM READMEs.
* New static/contract CTest and focused tests/integration/package-lifecycle client runner, production-helper repackaging, native access test, reproducible runtime recipes, compact evidence/private-client-permissions.json.
* docs/private-client-permissions-validation.md contains exact commands, results and limits.

## Validation
* Fresh CMake configure PASS: /tmp/fic-client-permissions-check; affected CTest8/8 PASS, five static labelled. /tmp/fic-client-{configure,ctest}.log. DEB dependency and Qt bundle tests directly PASS as well.
* Actual client DEB/RPM archives built via current production helpers:20 archives (client pairs0.1.1→0.1.2 across5 distro rows). DEB archive IDs root:root0750; native configure root:fic0750. RPM archive and installed attrs root:fic0750/bin2750.
* Native Debian12/13, Ubuntu24.04/26.04 and ALT p11 ALL PASS install/reinstall/upgrade and independent metadata check after each client, real non-root CLI,30 Qt/Xvfb xcb/JPEG/private-Qt launches,45 outsider EACCES proofs, no group write, unchanged owner/group/mode/inode/mtime/ctime/content for persistent metadata fixtures (config/DB/journal/witness/incident/log/notify). DEB unsafe type/link/owner/writable path refusals PASS.
* Final native-only rerun all5 exit0; raw build-package-lifecycle/client-access-<row>/{build.log,native.log,packages/,results/}. Compact tracked receipts contain source/image-independent OS/manager facts, source/package/raw-evidence hashes and results.
* Bash syntax, Python compile, final diff check PASS. No full C++ build/CTest; no production C++/install-layout changes.

## Remaining / limits
* No required permissions work remains. Repackaged unchanged native cached FIC ELF payloads, not current-HEAD release rebuilds. Dependency admission bypassed (dpkg --force-depends/rpm --nodeps); not a full clean-system daemon stack install or GUI/IPC functional-policy claim. GUI tests really create QWidget/event loop, not just test-x.
* Existing main FIC root initialization is seeded in RPM fixture; main fic.postinst never used to fix clients. Native metadata fixtures are not a live daemon journal.
* Ubuntu24 root dist old GUI lacks smoke flag; newer real cached distro artifact from dist/pam-activation/ubuntu2404 used with hashes. Missing image libraries fixed only in test images. Docker socket/old build-host SSH unavailable; official Docker Hub ALT p11 + verified HTTPS mirror used after ALT registry timeout.
* Earlier PAM I6 evidence remains historical; do not relabel it for this packaging-source change. No native host state changed, no image/container pruning or push.
