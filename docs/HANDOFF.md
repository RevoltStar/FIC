# Current workspace

## Current base
* Branch `main`. I6 completion snapshot on parent `4717cfd4af6df9297b1a6234759258a415dcea34`; the containing commit is the single I6 completion commit. No push.

## Current task
* I6 production SSSD integration (attachment a193b4cc): implementation and acceptance complete. No next implementation stage started.

## Accepted architecture / invariants
* All three actual PolicyRegistry policies use the same I1–I5 coordinator/resource mutex. No competing legacy writer, second restart engine, adoption, migration or package-lifecycle expansion.
* Offline: integer0..3650/default30; cache: fixed true; account: explicit integer0..3650/no default. Offline→cache Recommended only. GUI unset integer stays empty; metadata default is null.
* Current registry/configuration is bound through captureConfigurationVersion. Disable physically releases, saves explicit durable DISABLE with CAS, reloads registry, then rechecks all remaining ENABLE expectations (distinct from journal owners), physical/surviving ownership and runtime under the same mutex.
* Production release payload v3 retains minimal structured observations directly from successful I3; global journal schema remains3. Offline uses stopped epoch/absence, no process receipt. Existing journal supplies integrity/durability; no extra crypto store. Private typed acknowledgement atomically completes RolledBack and surviving container witnesses. saved/applied remain separate.
* Historical v1/v2 readable unchanged; v2 awaiting without sufficient receipt refuses, no reconstructed history/restart. Legacy scalar Applied/Prepared/RollbackFailed refuse production apply/release with provenance retained. Uninstall uses ReleaseOnly, leaves configured ENABLE/value unchanged.

## Completed / changed areas
* Policy/registry no-default metadata, current-registry binding, GUI editor and enable validation; three policies/config entries/RU+EN localization; optional native SSSD trust catalog across all five platforms.
* Coordinator production intent/release/ack, v3 codec/receipt and typed journal finalization; daemon disable/reload/results and uninstall no-owner full-union proof.
* Native-discovered fixes: keep/rebind journal value snapshot across validation reload; valid surviving0640 owned file must not go through legacy0600 absence classification; preserve native alias-code pins in receipt; machine procfs parsing uses classic locale (ALT ru_RU grouping otherwise breaks numeric maps parsing).
* Tests separate explicit historical legacy specimens from production refusal. New source-bound actual-package native harness/evidence under `tests/integration/sssd-i6/`; historical R1–I5 reports/indexes preserved. I5 checker now authenticates its immutable accepted sources.
* Authoritative integration contract: `docs/sssd-verified-activation-design.md`; runner scope/preparation: `tests/integration/sssd-i6/README.md`; API/default/editor and user behavior: `fic/README.md`.

## Validation
* Full configure/build all production+test targets PASS, Docker `fic-sssd-i1:full`, Debian12 profile: `build-sssd-i1/full/i6-final-full-build.log`.
* Full CTest PASS:217 PASS,0 FAIL,4 opt-in native SKIP /221,130.88s, including I6 evidence guard and I1–I5/journal/SSH/PAM/SUDO/USER_CREATION/registry/dependency/GUI regressions. Log `build-sssd-i1/full/i6-final-ctest.log`. Skips: verified_config_service_native_tests, daemon_singleton_startup_native, maintenance_preflight_native, package_pam_hooks_native.
* New production-policy and Qt no-default editor executables also PASS as UID65534 with read-only host mounts; direct execution used because CTest itself needs a writable Testing log directory.
* Five clean actual-package builds PASS, same960 source inputs,3 packages per platform. Historical actual packages built from exact parent/tree at lower version0.0.0-a; paired symbol Build IDs checked by debugger fixtures.
* Native I6 matrix PASS110/110:22 scenarios each Debian12/13, Ubuntu24.04/26.04, ALT p11. Real installed daemon/CLI/IPC/packages; Apply/same-value/Refresh, two domains/three owners, active/offline disable and no-owner siblings, crash/retry, CAS/cleanup/journal/registry/receipt/physical faults, legacy upgrade and remove/purge/refused release. Raw results `build-sssd-i6/<platform>/native`; retained230 compressed reports plus `evidence.json`. Collector and check-evidence.py PASS with current source/harness/package bindings.
* Python compile, shell syntax, git diff --check and cached diff check PASS. No build artifacts or __pycache__ staged.

## Remaining / evidence boundaries
* No unfinished I6 implementation or acceptance blocker. Four separate opt-in native CTest gates above were not run; the explicit I6 Docker matrix was run independently.
* Closed admitted native profiles and explicit LDAP/password roots only; AD/IPA/proxy, dynamic/trust scopes and unproved launch/consumer topology remain unsupported. Preprepared private mount boundaries and native trusted metadata are deployment prerequisites, not provisioned by FIC.
* Isolated containers/no host network or security mutation. No production authentication, future LDAP availability, real-host boot or days-long credential/cache cleanup claim. ALT fixture explicitly supplies native EnvironmentFile when absent.
* Old scalar producer requires0600/root, incompatible with active native D13/U26 metadata. On those two profiles, actual old records are generated offline, followed by explicit fixture SSSD start before upgrade; this is not old active-writer support or an I6 recovery/migration. Legacy ownership requires preserved config/journal/artifacts and a separately reviewed administrative resolution; no blind deletion or forced uninstall.
