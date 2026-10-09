# FIC handoff

## Current base

* `main`, task base `2efd2644d7850459a0195bde6d01b185c8e477bb`.

## Current task

* Complete Pre-Login Gate attachment `7012859f-fb78-4662-af95-5ba13452632e`: two sequential focused commits. Headless stage complete; Qt EGLFS/KMS stage next.

## Accepted architecture / invariants

* Gate is systemd/UI only: no authentication, policy apply, mode/severity/PAM mutation or direct DM start. Manual handoff always available.
* Auto-handoff requires trusted first-apply result and startup lifecycle, current kernel boot ID, kernel peer PID (and observed systemd MainPID), proven mode/readiness. Systemd READY/StatusText is display-only.
* Oneshot + RemainAfterExit, Requires/After DM drop-in, Wants fic without After/Requires fic. Checked helper changes only exact managed drop-in and proves effective graph. Inverse After from gate's Before survives detach but does not pull gate into transaction; removal rejects remaining Requires/Wants/BindsTo/Requisite/Upholds.
* Planned graphics: root broker for IPC/power/VT, dedicated unprivileged system-Qt frontend under `/usr/libexec/fic`, private inherited status/action channel. Parent must reap frontend before successful handoff; no bundled xcb runtime reuse.

## Completed / changed areas

* Strict shared readiness serializer/parser; real access client schema mismatch fixed. First startup result stored in daemon memory, independent of periodic apply.
* Headless controller/provider, console tty7 gate, bounded systemd observer/logind power actions, unit and checked activation/deactivation helper.
* Optional DEB/RPM package with explicit upgrade/removal/recovery dispatch; offline removal supported. Template accepts protected root:fic 0640; installed /etc drop-in stays root:root 0644.
* Unit/real transport tests, generated maintainer script tests, guarded disposable VM status fixture, real PAM account probe and S1–S8 harness. Authoritative documentation: `fic-prelogin/README.md`.

## Validation

* Fresh Debian 12 full configure/build PASS; full CTest excluding root-sensitive mutation_journal_tests 168/168 PASS; mutation_journal_tests separately under UID1000 PASS. Logs `/tmp/fic-prelogin-debian12-build/{full-build,full-tests,journal-tests}.log`.
* Executable RED-before against base access client rejects real serializer's allow response; new client GREEN. VM S8 RED exposed inverse ordering edge and harness masking; corrected S1–S8 + reinstall/remove/purge PASS.
* Disposable Debian12 QEMU/TCG VM: real systemd/LightDM alias graph with test sleep ExecStart override PASS. Actual LightDM and autologin PAM account stacks: OFF/PASSIVE neutral without daemon; ACTIVE missing daemon/ISOLATE deny, READY allow; local root recovery PASS. Logs `systemd-vm-tests.log`, `pam-vm-tests.log`. No host security changes.
* Headless targeted configure/build/IPC tests Debian13, Ubuntu24.04/26.04, ALT p11 PASS; Ubuntu26 needs libpam0g-dev installed in disposable image. DEB/RPM artifacts built through production functions; DEB VM lifecycle uses force-depends because base binaries were staged independently, not installed as a fic package.
* Generated package scripts and shell syntax PASS; git diff --check PASS.

## Remaining

* Implement/test Qt frontend, broker supervision, trusted plugin paths, console fallback and DRM/stock-DM handoff. No graphics/GPU E2E claim yet; distro VM matrix beyond Debian12 unavailable.
* Disposable VM assets: ignored `build-prelogin-validation/vm/`; loopback SSH 2222/QMP4444; Docker `fic-prelogin-vm:debian12`, running `fic-prelogin-vm`. Dedicated SSH key inside ignored directory. DMI/marker required before guest mutation.
* Current builds `/tmp/fic-prelogin-debian12-build`, `/tmp/fic-prelogin-cross`. Graphics draft in `/tmp/fic-prelogin-graphics-draft` has not been applied or validated.
