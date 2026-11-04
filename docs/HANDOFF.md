# Current workspace

## Current base
* Branch `main`; SYSCTL task base `9c6800c5e1ca2bff2bb0723f51b984ffa5bee559`.
* Completion changes belong to the commit containing this snapshot; no push.

## Current task
* Attachment 5c51f357: SYSCTL owned apply/REFRESH and release via native exact prefix. Implementation and required validation complete.

## Accepted architecture / invariants
* Every successful ENABLE apply owns its parameter in `/etc/sysctl.d/zzzz-fic.conf` and journal, even matching foreign/runtime state. No blocks, foreign effective parser, adoption, runtime-history restoration or compensation.
* Metadata-only directory/name priority, symlinks/null masks; any selected regular late `.conf` blocks apply before policy mutation. Native loader/executable preflight uses existing platform resolver/trust and typed systemd properties.
* One SYSCTL mutex. Fresh/REFRESH typed intent preserves ID/predecessor; durable attempted checkpoint before CAS. Direct inline NotInstalled permits no-effect abort; uncertainty stays Prepared and blocks writers. No postrestart inference of no effect.
* Global journal schema remains3; optional SYSCTL undo extension version1. New container creation/current device+inode witness is recorded honestly. Shared witnesses update atomically with transaction completion. Replaced containers cannot be adopted/deleted with stale creation authority.
* Existing old key/value records retain legacy empty-container release exception, NOT creation proof. Mixed new owners can reference the specific existing legacy origin without claiming creation; referenced origin cannot be discarded. No migration subsystem.
* Release preserves other keys, conditionally writes/deletes, requires durability and completes journal before verified `systemd-sysctl --prefix=/canonical/leaf`. No runtime value read on release; absent foreign source may keep runtime. Native helper failure/exception is warning, without re-enrollment/retry store.
* Existing optimistic CAS/root-writer race boundary remains. Unknown/orphan physical state is never automatic success.

## Completed / changed areas
* SYSCTL configuration/transaction/native helper, production apply and RollbackExecutor integration; optional SystemdSysctl executable in five profiles, resolver and profile validator.
* Narrow journal prepare/attempt/finish/abort; atomic shared-witness updates; no changes to other backend behavior, package scripts/lifecycle, SysctlKey or SysctlRuntime.
* Unit/static checks updated, dedicated ownership regression suite and five-platform native fixture added. Obsolete foreign-effective RemoteSysctlIntegration.sh replaced by isolated native gates.
* Authoritative contract/table/production-file list: `docs/sysctl-lifecycle.md`; related rollback/architecture docs updated.
* Compact source/image/ELF-bound receipt: `tests/integration/sysctl-ownership/evidence.json`. No bulk gzip reports.

## Validation
* Final full project build and actual DEBs in prepared Debian12 Docker builder PASS; `build-sysctl-validation/full-build-package.log`.
* Full Debian12 CTest with DAC override capabilities dropped and Git safe.directory supplied: 219 passed,0 failed,4 opt-in native skipped,223 registered (165.76s). Includes journal/rollback/SSH/SSSD unit/static checks and historical I6 evidence (historical only).
* Native SYSCTL + two unit suites each: Debian12(systemd252.39), Debian13(257.13), Ubuntu24.04(255.4), Ubuntu26.04(259.9), ALT p11(258.9) PASS. Actual helper paths, source priorities/masks, exact leaf/dotted interface, unrelated leaf unchanged, owned no-op/REFRESH/release, warning failures and loader refusals tested.
* Real Debian12 FIC daemon/CLI/package scripts: apply/no-op/runtime repair → prepare-uninstall/rollback all → remove/purge PASS; foreign source and administrative policy config preserved. Installed ELF matched explicitly rebuilt daemon SHA.
* Source-manifest recheck, Python/shell syntax and `git diff --check` PASS. Reproduction: `tests/integration/sysctl-ownership/README.md`; local logs under `build-sysctl-validation/`.

## Remaining / limits
* No unfinished required SYSCTL implementation items. No host security mutation; native runtime containers have private namespaces/no host binds/network/ports, global kernel sysctls/sysfs read-only, private net leaves writable only.
* Supplemental ALT `platform_profile_tests` fails `SDDM configuration path is incorrect`; reproduced unchanged from clean task-base archive in separate native build. Unrelated baseline defect, intentionally not fixed; full compiled-profile validation in SYSCTL driver passes all five.
* Actual package E2E is Debian12 only; other four have real backend/loader gates, not package E2E. No real host reboot/power loss or arbitrary kernel-knob coverage. Durability/CAS uncertainty uses deterministic fault injection and remains fail-closed; no new automatic recovery engine.
* Four opt-in CTest skips: verified_config_service_native_tests, daemon_singleton_startup_native, maintenance_preflight_native, package_pam_hooks_native. Separate required SYSCTL/package native gates above were actually run.
