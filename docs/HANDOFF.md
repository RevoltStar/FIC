# Current workspace

## Current base
* Branch `main`. Production lifecycle implementation: `752354c`; platform prerequisite: `6676a79`. The accompanying validation/docs commit contains the native runners and final evidence. No push.

## Current task
* Attachment161a3ab3: replace unfinished M1 with daemon-owned uninstall and a real, installable DEB/RPM lifecycle. Implementation and final five-distro package gates completed. This is not the earlier runtime/finalizer design.

## Accepted architecture / invariants
* AGENTS17 and `docs/package-lifecycle.md` are authoritative. Four durable states; daemon-only ownership release; infrastructure-only helper in existing fic-dick dependency; no runtime/finalizer/offline undo/legacy migration/adoption/cancel-uninstall.
* Keep daemon.lock, journal schema, ownership/CAS and domain backends. Active Ubuntu/ALT SSH release still requires administrator stop. Override never waives actual stopped-writer/PAM-reference proofs. Late DEB purge without ELF uses prior Removed under lock and retains restrictive marker.
* Native tests run in disposable private systemd PID1 containers, without host mounts/ports/network, with per-mount readonly sysfs and own writable cgroups. No host policy/device mutation.

## Completed / changed areas
* Shared PackageState; daemon admission/startup/IPC/prepare/rollback all/periodic/session gates; explicit install proofs; CLI; device and prelogin admission. Reverse Required groups and shared-resource uninstall targets preserve desired config and retained failure provenance.
* Secure override parser; closed infrastructure helper; actual DEB/RPM templates/builders; configuration/journal/witness retention and late purge. Old production M1 coordinator/state/runtime prerequisite/manifest/masks/transaction-lock/offline release removed. Historical research marked superseded; current contracts/packaging docs updated.
* Native fixes include current C2 password preflight, missing-but-failed empty unit proof, fresh dependency state, postinstall systemd reload and separate ALT fic-dick bootstrap for supported retained-state reinstall. Unknown/untrusted state remains rejected.
* Native runners, real-package drivers and compact evidence: `tests/integration/package-lifecycle/`. Final acceptance/limitations: `docs/package-lifecycle-validation.md`.

## Validation
* Full Debian12 project configure/build PASS. Full CTest excluding journal permissions fixture: 199 PASS, 4 opt-in SKIP, one stale platform static-check failure; corrected assertion and 6 affected tests rerun PASS. Journal fault-injection separately as UID1000 PASS. Thus 201 distinct normal tests passed after the targeted correction; four normal opt-in skips documented. No remaining failed check from that run.
* Actual singleton startup and readonly maintenance native gates explicitly run PASS. Restricted real daemon: denied mutations, no malformed config/journal repair, periodic suppression, SIGKILL/restart and PID1/container restart with fresh /run all PASS. Actual late postrm lock-contention failure/retry without main ELF PASS.
* Real FIC packages v0.1.0→0.1.1: Debian12 (including optional prelogin), Debian13, Ubuntu24.04, Ubuntu26.04 and ALT p11 final gates PASS. apt/dpkg install/upgrade/configure failures/retry/remove/purge/reinstall; RPM install/upgrade/erase/retained-state reinstall; active PAM/shared Sudo/login.defs release; partial rollback+retry; emergency broken ELF/journal and foreign-PAM refusal. Exact commands/exits/state hashes and archive digests committed as evidence. These are not dummy package tests.
* Bash syntax, Python driver compilation and git diff --check PASS. Raw build/CTest logs remain in build-env-full-debian12; unique package evidence directories are referenced by committed summaries.

## Remaining boundaries
* Real PAM user authentication, physical device enforcement, graphical boot, physical VM reboot and live SSH continuity were not validated; do not imply them from package gates. Other backend release algorithms have unit/fault-injection evidence, not all physical native mutations.
* Under simultaneous compilation/multiple native runs, device readiness sometimes exceeded its existing 30s bound and configure failed. Exact cause unproven; final repeat matrix passed without changing timeouts. Bounded readiness can require a safe package configure retry under load; failures are retained, not counted as PASS.
* Arbitrary legacy development scriptlets remain unsupported; no guarantee of refusal before an old scriptlet. No automatic migration or ownership adoption.
* Docker is working; six pre-existing data volumes were preserved. Native images/caches occupy disk. Use DOCKER_CONFIG=/tmp/fic-package-docker-config (empty config) if the absent Windows credential helper interferes. Do not factory-reset/delete volumes.
