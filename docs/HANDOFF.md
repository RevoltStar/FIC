# FIC handoff

## Current base

* Branch `main`; parent commit `041854677a6a2c2bb1ca7f4fc4af924756b8eb7d`.

## Current task

* Incident Response PAM access gate and daemon readiness stage is implemented in this commit.

## Accepted architecture / invariants

* Ordinary account login requires one live daemon reply, readiness `READY`, proven persistent state, and severity `UNLOCKED` or `SOFT`; every other result denies. The same main loop handles IPC and policy apply, so a blocked apply leads to the PAM client's bounded two-second timeout.
* `pam_fic_access.so` runs only in PAM `account` with `required`; it is neutral for services outside each `PlatformProfile` login list. Trusted local root on `login` and a target-user member of `fic` with securely proven `lock_exempt_fic_members.status=ENABLE` recover before IPC. Broken or missing `GLOBAL.conf` disables group recovery, never local-root recovery.
* PAM uses the compiled production socket, checks daemon `SO_PEERCRED` UID 0, and validates the full `access_gate_status` reply. `FIC_SOCKET_PATH` cannot redirect it. The daemon proves module loadability and effective account topology before `READY`; the same proof feeds `IncidentController::pamGateActive`.
* Debian/Ubuntu package lifecycle owns a permanent `pam-auth-update` account profile. ALT attaches a transactional marked rule to `system-auth-common`; erase detaches it only after provider release, while upgrade keeps it. The gate is independent of raise/clear.
* `IncidentResult::persistentStateBroken` reflects observed persistent provenance independently of containment status. SSH has PAM-side support, but end-to-end SSH gating remains conditional until `ssh_use_pam` and effective `UsePAM` verification exist.

## Completed

* Added typed IncidentAccessGate metadata for Debian 12/13, Ubuntu 24.04/26.04, and ALT p11; module, secure recovery reader, target-user NSS membership check, strict client, read-only daemon IPC, readiness transitions, topology verifier, packaging hooks, and focused tests.
* Controlled services cover `login`, `sshd`, SDDM/LightDM normal and autologin, GDM password/autologin/fingerprint and distro-specific smartcard entry points. Greeters and general PAM consumers remain neutral. Official distro PAM package files were inspected to establish these routes.

## Validation

* Fresh Debian 12 container: full configure/build passed; `ctest -N` found 132 tests; root CTest excluding `mutation_journal_tests` passed 131/131; that test passed separately under UID 1000. The all-root CTest run failed only its chmod-denial injection because root bypasses mode permissions.
* Debian 12/13, Ubuntu 24.04/26.04 installed topology checks passed with real display-manager PAM files and generated `common-account`. ALT p11 runtime verifier passed with official `login`, `openssh-server`, `gdm-data`, `sddm`, and `lightdm` RPM PAM files, including `gdm-smartcard` through `system-auth-pkcs11` and `system-auth-common`.
* Debian and ALT `ldd` showed no missing module dependencies. Debian staged CMake install placed the module under `/lib/x86_64-linux-gnu/security`. Isolated libpam smoke passed local-root recovery, remote-root denial, ordinary/autologin denial, and neutral `sudo` behavior.
* PAM packaging checks, platform static checks, shell syntax checks, and `git diff --check` passed. Ubuntu 26.04 affected targets/tests passed in the existing builder with temporary PAM headers; rebuilding that builder hit an external Ubuntu `libpng16` mirror error.

## Remaining

* Session/network containment, boot guard, display gate, and effective SSH `UsePAM` proof belong to later stages. Full DEB/RPM install, upgrade, and erase were not run; lifecycle scripts have static/fixture coverage. No host PAM files were modified or runtime policy apply performed for this validation.
