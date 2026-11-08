# Current workspace

## Current base
* main; I6 base `db7a1d270404340de1e77eb6da91ce5d8e2d482d`.
* This changeset: `test(pam): validate native functional policy lifecycle across platforms`. One completion commit; no push.

## Current task
* Attachment cf197d90: mandatory I6 L1/L2/L3 matrix complete. Full daemon/CLI L4 remains explicitly not proven, as allowed by the task's production-class driver boundary. Stop after this task.

## Accepted architecture / invariants
* No production files changed. R1–I5/C2/Required/ownership/markers/schema/package lifecycle unchanged. No new policy/enforcement/recovery engine.
* L1 fixtures, L2 actual production registry/planner/classes/journal and L3 actual Linux-PAM consumers are separate; none implies full daemon/service E2E L4.
* All PAM/shadow/TCB/account changes only disposable Docker. Non-root self-change uses real UID>0/EUID0; root differentials recorded separately. System root never locked. No plaintext passwords in final evidence.
* Independent D12 History scalar options and ALT legacy History scalar options remain NotEnrolled: independent undo NOT_APPLICABLE, no historical scalar restore; capability ownership release separately proven. ALT causal ownership/ABA and non-cooperating-writer CAS limits remain.

## Completed / changed areas
* Existing pam-dependencies Driver: closed persistent test mode with real registry/planner/rollback and real config/journal; audit now calls production effectiveRollbackEnrollment. No scope narrowing.
* Existing C consumer: correct multi-message INFO/ERROR handling, current/new routing, auth+account and UID/EUID. Added pure conversation CTest. Runtime recipe uses native distro packages/dictionaries, no fake stock templates; ALT includes passwd/login/sshd/sudo/su.
* Existing C2 test targets: fixed missing SudoersDisabledWrapper.cpp linkage; wiring target links concrete History policies. Provider-option adapter now initializes test config/runtime and calls public typed concrete policy apply(), not unnamed protected applyPam. D13 ProviderConfigFile routing comment corrected; gate binary/package receipts added.
* Native matrix: D12/D13/U24/U26/ALT each fic +23 relevant test targets, 25/25 CTest + production registry/Required audit. All registered parameters (16 each D/U, 12 ALT) apply/repeat/refresh/release; Q/H/L combinations; root/window controls; shadow/TCB digest checks; lockout/reset; both ALT strategies + native pwtxn contention; post-release consumers. 246 main consumer operations PASS.
* Supplemental PASS: D12 ModuleArguments window/pure-refresh zero pam-auth-update; D13/U24/U26 ProviderConfigFile window 2→4; four native foreign-faillock no-adoption/no-double-count/preservation cases; four real PAM module>primary>drop-in precedence calibrations (explicit synthetic L3 service); ALT su PAM consumer + current installed-services control/foreign-history release; all5 parser probes (not enforcement evidence).
* Legacy options-gate root checks are return-code-only and not independently credited as strict root proof. Main matrix supplies UID/EUID + hash proof.
* Research §14 + compact evidence: tests/integration/pam-dependencies/i6-evidence/summary.json. Historical R1–I5 untouched; docs/rollback.md unchanged. Raw before/after config/PAM/journal/request/binary/image/package receipts in ignored build-pam-i6. Root-owned journals retain permissions; hashes read through read-only Docker.

## Validation
* `FIC_PAM_GATE_STAGE=i6 bash tests/integration/pam-dependencies/run-i1.sh TAG PLATFORM BUILD_DIR` and `bash tests/integration/pam-dependencies/run-functional.sh TAG BUILD_DIR` all5 PASS.
* Before/after source receipts all5: `6c076b980a6999d2e5e6429583f6db8da08dca6656c491ac674a5871ae3a1bbe`. Runtime recipe/image/package identities separately recorded.
* `python3 tests/integration/pam-dependencies/check-i6-evidence.py build-pam-i6` PASS current source; nine checker positive/negative tests PASS. Required scenarios, source freshness, missing reports, UID/hash errors, active terminal ownership and credential leakage checked. All native final journals have no active ownership.
* Existing options gates and check-i5-control.py PASS. Bash syntax, py_compile, evidence bindings/consistency and git diff --check PASS.
* Initial cracklib absence was environment failure. Initial driver load/factory/setup errors and weak old-token History oracle corrected before final runs; root oracle now uses proven recent token and freshly saved previous credential. No confirmed new production defect.

## Remaining / limits
* No unfinished mandatory I6 functional work. No full project CTest, actual daemon/IPC/systemd/package L4, GUI/domain infrastructure, separate direct use_first_pass consuming-path proof or automatic unlock/interval-expiry proof (reset only). Lockout root flag L2 only; no root lock experiment.
* Development binaries report version 0.0.0-alpha/build_commit unknown; actual current source/binary hashes recorded, not release-artifact attestation.
* Provider-owned history/TCB data retained on release; ALT legacy scalar values may remain by existing contract. Do not add migration/adoption/stronger causal markers automatically.
* Caches: build-pam-i1/{debian12,debian13,ubuntu2404,ubuntu2604}, build-pam-r1-i3/alt-p11. Runtime images fic-pam-i6-native:TAG. No running test daemon or host PAM changes.
