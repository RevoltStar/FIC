# Current working state

## Current base
* `main`; latest legacy-admission research stage see `git log -1`; coverage `95e72ca`, payload/deferred-proof `32d9c0e`. No push. M1 unfinished; SSH Stage3A deferred.

## Current task
* Finish M1 attachment `9aef83ea-6744-4c0f-b167-aa1f49d956c5`, autonomously; no checkpoint-only stop.
* Current stage: accepted incompatible-legacy refusal boundary; native dependency/admission matrix establishes a further technical blocker (see below). No production guard or preparatory migration added.

## Accepted architecture / invariants
* AGENTS.md §17, `maintenance-runtime-package-design.md`, `maintenance-finalizer-retry-lifecycle.md` authoritative.
* One engine/daemon.lock; closed fixed package-session, no arbitrary executor/FD authority/bypass.
* Durable root-controlled fence/tombstone outside deleted trees. Persistent unit masks + actual cgroup/process/image proof; independent manual legacy execution administratively excluded, unknown writers refuse.
* Preliminary runtime owns same ELF; exact native version/ABI/order. Two-stage runtime erase requires prior completed transaction removal proof + fresh proofs. Joint autoremove may refuse.
* Postinst InstalledButFenced; deferred finalizer actual PM locks + daemon admission through proofs; recurring bounded-cost retries, no total cap/watcher. Structural failures remain fenced.
* Upgrade only quiesces, preserves policy/PAM ownership; Remove performs release. Missing/unknown/corrupt lifecycle state refuses, never manually synthesize Installed.

## Completed / changed areas
* Early DaemonInstanceLock; M1-A/B standalone admission; typed schema2 lifecycle store/durable snapshot CAS; immutable mask ledger, image/script writer inventory, actual systemd/cgroup/procfs quiescence and retained identities after original ELF removal.
* `PackageDatabaseReader`: strict native installed/incomplete distinctions and RPM EVR/duplicate refusal, real manager locks through query. Unlocked runtime prerequisite observation explicitly NOT finalizer proof.
* `PackageLifecycleCoordinator.prepare`: immutable plan/inventory before fence, same hash-store lock across publication, fixed install/upgrade/remove preparation. Runtime binding compiled version/ABI + configured DB identity + exact executing trusted runtime inode.
* Closed CLI package-prepare install|upgrade/version/ABI; package-release remove/version/ABI. Remove performs read-only preflight before stop and holds one guard through preparation/domain release/hooks/final read-only proof to ReleaseComplete, still fenced.
* Shared existing resource engines: ALT pwhistory→faillock before DM→DE→provider→password; independent read-only journal/domain/hook proof. ALT advisory status does not write PID/debug state. Fixed hook detach preserves gate until other hooks/loadability proofs, no compensation/adoption.
* Daemon + conflicting standalone mutators fence-check before config/journal/SSH containment; trust-sync early + recheck under existing hash-store lock callback. Read-only routes preserved.
* `PackagePayloadManifest` + staged Python producer: bounded exact immutable SHA256/metadata/symlink targets, fixed trusted first-component usr-merge aliases, separate known managed PAM roles. Not ownership/lifecycle authority. Build-time output outside its own staging tree.
* New native coverage stage: fixed `readOwnedPaths` query under matching PM locks, strict bounded path parser, `proveComplete` rejects omitted non-directory payload/unowned manifest entries/unsafe directory/symlink. No arbitrary metadata exclusion. Main finalizer not yet integrated.

## Validation
* Current research/CMake stage: full D12 configure/build + CTest GREEN 206 PASS / 4 expected native SKIP (210), 173.18s: `legacy-admission-full-debian12.log`. Two new tests default skip without FIC_LEGACY_PACKAGE_ORDER_NATIVE; manual fresh native matrix runs separately. Opt-in native CTest D12 registration check PASS (RED reproduced, not lifecycle safety): `legacy-predepends-ctest-native-debian12.log`, 1.16s.
* Current legacy admission research: 7 actual dpkg/apt scenarios × D12/D13/U24/U26 (28) assertions matched. Missing/never-configured cases preserve full protected snapshots; prior-configured cases REPRODUCED_RED with journal-path metadata changed. Logs `legacy-predepends-{distro}-{mode}.log`. Actual ALT dummy RPM Requires(pre)/failed %post/new %pre order reproduced, old product retained by independent refusal, `legacy-admission-alt-p11.log`. These are model gate/frozen old script/sentinels, NOT real journal/lifecycle PASS. New opt-in CTest research tests default skip 77; fresh disposable container required. Production C++ unchanged.
* Committed payload stage: full D12 configure/build + CTest 206 PASS / 2 expected native SKIP (208), 174.16s: `build-m1-evidence/payload-full-debian12.log`.
* Current coverage: fic + 2 affected targets build, 2 CTest PASS `payload-completeness-tests.log`. Initial parser test caught repeated-slash normalization bug; fixed using exact string normalization, rerun GREEN.
* Native actual dummy DEB file-list under real PM locks PASS Debian12/13/Ubuntu2404/2604: `file-list-native-*.log`. ALT actual dummy RPM PASS in `file-list-native-alt-p11-history.log`; includes failed harness attempts (missing rpm-build, root rpmbuild refused) and subsequent successful unprivileged build/query, then repeated-fixture refusal. Extra RPM build dependencies installed only disposable ALT container, not host.
* Final manifest coverage/byte/metadata tests including stricter usr-merge-leaf regression PASS all five native userspaces (`payload-coverage-native-*.log`). Full D12 current stage build + CTest GREEN 206 PASS / 2 expected native SKIP (208), 204.71s: `payload-coverage-full-debian12.log`. Final explicit-include fic/affected targets rebuild + 2 affected tests PASS: `payload-coverage-final-targets.log`.
* Confirmed legacy automatic abort RED on Debian12/13/Ubuntu2404/2604: `legacy-abort-native-*.log`, exact old fic-dick postinst/prerm from producer, failed new preinst → old postinst abort-upgrade mutates sentinel metadata 0600→0640 while independent daemon.lock held. Sentinel NOT actual journal. No actual FIC migration/recovery proof.
* Earlier native component preparation setup→PID1 restart→verify PASS five: `coordinator-native-*.log`. Hook/loadability/domain probes PASS five: `pam-hooks-native-*`. Full D12 prior stages GREEN; logs retained `build-m1-evidence/` (ignored).
* Actual FIC ELF dummy D12 prerequisite/preinst proof PASS (`runtime-entrypoint-native-debian12.log`, `runtime-entrypoint-refusals-native-debian12-green.log`), no security state changes; not actual complete FIC packages.
* Shell syntax and git diff --check PASS. Full host security state unchanged; tests only disposable containers/chroot.

## Remaining / blocker
* User accepted explicit incompatible installed-version/script refusal by preliminary runtime BEFORE any main/aux transitions. Unknown versions not compatible; separate preparatory transition NOT authorized to implement. Contract now in AGENTS.md and upgrade docs.
* **Confirmed architecture blocker:** exact DEB Pre-Depends accepts previously configured runtime=2 even after same-version reinstall/configure-a gate refuses. Separate direct dpkg, genuine local-repository apt upgrade and joint upgrade then run old prerm→new preinst refusal→old postinst abort-upgrade; old metadata mutation occurs. First refusal of NEVER-configured runtime is safe in the fixture, but this does not cover every required path. ALT Requires(pre) orders availability, not successful runtime %post; new main pre executes despite failure (independent main refusal preserves old dummy RPM). No production early guard can be claimed safe from dependency declarations alone. Need additional accepted per-transaction/deployment admission boundary; do not patch scripts/PM DB, add arbitrary executor, weaken fence or implement preparation as workaround. See `maintenance-legacy-compatibility.md` for matrix/evidence/options.
* Actual runtime package split/CMake install/staging and all main/aux DEB/RPM scripts NOT switched: still old unsafe between commands/ignored stop errors. No complete configure/recover/abort controller/finalizer/hook/path/boot/timer delivery.
* Before bootstrap: persist pre-unpack first-install absence/authority evidence. Installing alone cannot authorize neutralizing incident state or fixing /opt/fic authority after extraction. Existing/corrupt state must remain preserved, no adoption.
* Integrate manifests delivery in preliminary runtime, exact package/version/completeness cross-proof, fixed metadata-manifest identity policy, immutable operation-bound removal snapshot before deleting main payload. Read-only coverage currently does not authorize lifecycle transitions.
* Recovery must retain old maskOperationId with new opID/inventory; never unmask to create new plan. Only schema2 supported, no old development format migration. MutationJournal schema unchanged.
* Installed publication/final proof must take existing hash-store lock too; early/recheck callbacks alone are not full coordination. Runtime own removal cannot need already-deleted ELF; tombstone must survive.
* Actual FIC package full five-platform install/upgrade/downgrade/remove/purge/reinstall/abort/autoremove/partial/crash/reboot matrix still required. Component/research evidence is not lifecycle safety proof.

## Environment after reboot
* Docker works, ample disk. Five `fic-m1-masks-*` systemd fixtures running; source RO/no host security mounts. D12 has dummy fic-runtime with earlier real ELF (before package-release route), dummy fic-m1-entrypoint-fixture + canonical Installing fence/masks. /opt/fic absent. Do not treat as clean fresh install or manually clear state. Other four fixtures have private component Installing fence/masks.
* `fic-m1-rpm-order:tooling` test image committed from disposable ALT file-list container for rpm-build tools (dummy fic-cli, no actual FIC). New `fic-m1-alt-filelist` disposable stopped container has rpm-build + dummy fic-cli only, no actual FIC installation. Full log contains native PASS. No need repeat existing fixture without explicit test cleanup.
* Build `build-env-full-debian12` one writer only. Use git safe.directory /src and drop DAC_OVERRIDE/DAC_READ_SEARCH for full tests, FIC_DAEMON_SINGLETON_NATIVE=1 FIC_MAINTENANCE_NATIVE=1, QT_QPA_PLATFORM=offscreen. Mount source RO and build RW.
* New Python ignored globally: git add -f. Logs ignored, preserve build-m1-evidence across reboot.
