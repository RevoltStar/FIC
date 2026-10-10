# FIC handoff

## Current base

* `main`; task base `2efd2644d7850459a0195bde6d01b185c8e477bb`, headless commit `1eba2d8944adae0c6f8772dbef0f415de6b7cb6b`.
* Qt stage is complete in the commit containing this snapshot; use `git log -2` for its SHA.

## Current task

* Pre-Login Gate attachment `7012859f-fb78-4662-af95-5ba13452632e`: both focused stages complete. No subsequent refactor/deployment authorized.

## Accepted architecture / invariants

* Optional systemd start gate, not authentication or DM. Manual handoff changes no policy/PAM/incident state; systemd starts DM after successful gate exit.
* Auto-handoff needs trusted current-boot first apply/lifecycle/readiness and renderer-ready acknowledgement. Systemd READY is only display progress.
* Root VT/IPC/power broker; dedicated unprivileged system Qt frontend, inherited private channel, trusted plugin paths, seat0 DRM via sealed memfd. Cleanup requires renderer reap, keyboard/display/VT modes and termios restoration, broker-only cgroup proof.
* Oneshot/RemainAfterExit, DM Requires/After managed alias drop-in; Wants fic without After/Requires fic. Helper preserves vendor/admin units and refuses unproven detach/removal. No Delegate=yes needed.

## Completed / changed areas

* Strict shared status producer/parser, daemon startup result, access client schema fix, headless controller/helper, optional DEB/RPM lifecycle.
* Qt fullscreen/status/actions, UID/GID/FD/environment isolation, supervision/console fallback, cgroup proof, failed-unit removal, packaging/plugin dependencies and relevant tests/docs.
* Mode-unproven status cannot claim ordinary login allowed; OFF/PASSIVE PAM neutrality unchanged.
* Native crash regression fixed: Qt SIGKILL left K_OFF while broker remained alive; broker now restores captured keyboard/VT modes before text recovery.

## Validation

* Fresh Debian12 full configure/build PASS. Container commands: `cmake --build /build -j3`, `ctest --test-dir /build -E '^mutation_journal_tests$' --output-on-failure`: 170/170 PASS. Mutation journal executable separately under UID1000 PASS.
* RED-before baseline controller and shared status implementations fail new readiness/mode assertions; current tests GREEN. Evidence `build-prelogin-validation/final/{red/,build-final.log,ctest-final.log,journal-final.log}`.
* Configure/build + controller/IPC/process/offscreen Qt tests Debian13, Ubuntu24.04/26.04, ALT p11 PASS; final broker rebuilds PASS. Ubuntu26 PAM dev installed only in disposable image. Standalone graphics OFF with Qt discovery disabled configure/build PASS.
* Final DEB/RPM built through production functions; ELF/plugin-owner dependencies and ALT package names/unit paths checked. Generated maintainer dispatch/failure tests, shell syntax, git diff --check PASS.
* Guarded Debian12 VM: actual Qt EGLFS/KMS, evdev keyboard/mouse, manual/error UI, auto handoff, daemon loss, renderer crash/text recovery, leftover cgroup process denial, missing DRM, stock LightDM/Xorg/GTK greeter/restart, confirmed reboot and PowerOff during fixture APPLYING, broker SIGKILL/actual VT1 recovery, remove/purge/reinstall PASS. PAM/severity hashes unchanged. Logs `build-prelogin-validation/vm/{graphics-vt-fixed,graphics-remaining-final,graphics-poweroff-final}.log`, `serial.log` (kernel S5 power down). VM is powered off.
* Previous headless stage: real systemd S1–S8, installed LightDM/autologin PAM account probes, root recovery PASS; old /tmp logs lost on WSL restart. Current broader tests revalidate changed components.

## Remaining / limitations

* Native evidence only Debian12 QEMU/TCG virtio-gpu, Mesa LLVMpipe, system Qt6.4, stock LightDM/GTK. No hardware GPU or other distro/DM E2E claim.
* VM startup states use guarded read-only production-serializer fixture; no real full policy apply E2E. Optional DEB uses force-depends because daemon/PAM binaries are staged without a fic dpkg record; full base-package install/dependency lifecycle unproven.
* Root/external writer snapshot races and hardware driver behavior remain outside universal guarantees; see authoritative `fic-prelogin/README.md`.
* Ignored VM/build assets persist in `build-prelogin-validation/`; Docker `fic-prelogin-vm` exited after PowerOff. Never alter host DM/PAM/VT/security state for validation.
