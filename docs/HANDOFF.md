# Current working state

## Current base
* Branch main. Production B (this commit), parent audit A `1471349573f3ff8cfab0aa0cc9382ec02a345e15`; original Ubuntu base `f625f285c67681693703946df33725baa0d05420`. Exactly A+B; no push.

## Current task
* Attachment9b40fb0b: ALT p11 SSH verified activation. A audit and B production completed; no pending implementation for this task. Do not resume M1 or start another hardening phase automatically.

## Accepted architecture / invariants
* Authoritative contract: docs/alt-p11-ssh-verified-activation.md; sanitized B evidence: docs/alt-p11-ssh-policy-validation.json. Stock ALT openssh9.6p1-alt7/systemd258.9-alt1, canonical sshd.service, Type=simple/NotifyAccess=none, -D $EXTRAOPTIONS, required /etc/sysconfig/sshd; Pre keygen-A then sshd-t. Vendor unit unchanged.
* Closed AltSshSimple profile in the same RO engine, mandatory bounded readiness predicate: new invocation/process/exe, exact native endpoints/kernel sshd-owned listeners, no old controlled inode, SSH banner. No fake notify/new engine/watcher; Ubuntu socket/generator/FD inheritance stays separate. Default public generic notify contract unchanged.
* ALT /etc/openssh/sshd_config stock has no Include. Unused systemd external symlink in sshd_config.d is not captured. Optional existing admin sshd_config.local.d, exact manifest/relative base /etc/openssh; FIC never creates/includes it. Main/env/all3 stock key pairs referenced, -A must be no-op; missing/unsafe/untrusted keygen refuses pre-save.
* Strict enabled/ready admission, no hidden enable/start/unmask/reset-failed or fallback. Same shared mutex, Prepared gate, CAS/durability, R1/R1b/R5 provenance, A/B/C/P and bounded in-memory receipt (including ALT listener/keygen identities). Unsafe owned-value REFRESH still refuses.
* Active ALT rollback refuses before config write; offline loaded inactive/dead/MainPID0/noJob/noTrigger proof permits conditional ownership-only release, journal RolledBack and explicit runtime NOT activated. Unknown/unloaded refuses. Schema/M1/packaging unchanged.

## Completed / changed areas
* AltVerified platform dispatch/keygen catalogue; parameterized SSH input profile; shared listener observation extracted from Ubuntu; AltSshServiceFlow; typed offline release profile; generic closed simple callback; adapter/module/provenance source lists and tests.
* Guarded native runner/Driver/alt_service.py exercises real five policy classes/journal/adapter on stock ALT. RU/EN descriptions, adapter/lifecycle/ALT docs, TODO updated.

## Validation
* ALT audit28 PASS; full production all phase64 PASS/0 FAIL/0 SKIP. Stock/fresh5, no-op receipt, v4/v6 Port, Include/Match/env/keys/dropins/state matrix, pending/auto-restart, deterministic CAS/post-save/Prepared/journal/unknown-writer/cleanup/drift/readiness/listener faults, active refusal/offline release.
* Real Debian12/13 each30 generic +59 adapter +24 module groups PASS; Ubuntu24/26 each51 socket-policy groups PASS (final runners exit0). Portable pure adapter contract CTest PASS on all5.
* Generic native: ALT201 PASS1 SKIP (no stock lower-layer empty SSH Include fixture); D12/D13 each201 PASS0 SKIP; U24/U26 each202 PASS0 SKIP. SSH provenance/rollback each55 PASS, D12/D13 additionally3 real OpenSSH probes each. No FAIL.
* Full D12 configure/build PASS, CTest208 PASS/0 FAIL/4 SKIP: privileged PID1 generic native (separately run all5), opt-in package PAM hooks, legacy DEB/RPM reproductions. Final related descriptor/resources/SSH CTest6 PASS; Python AST/bash syntax, audit safe-guard self-test, RU/EN description checks, git diff --check PASS.
* Commands: openssh_native/run-native.sh IMAGE PROFILE (all5); verified_config_service/run-native.sh IMAGE PROFILE (all5); ssh-provenance/run-native.sh debian12 debian13 ubuntu2404 ubuntu2604 alt-p11. Full logs build-env-full-debian12/alt-final-{build,ctest}.log; final ALT /tmp/fic-alt-full-final.log; reports build-openssh-native/PROFILE/evidence/results.json. Quantitative durable summary in B evidence.

## Remaining / limits
* Next separately authorized stage: installed FIC on VMs across all5 platforms, including daemon/IPC/package/PAM-login acceptance. Current gates use real components in guarded disposable systemd PID1 Docker containers, shared WSL2 kernel6.6.87.2; not independent VM/kernel validation. No host SSH/PAM/network operations.
* Real-host private publication boundaries remain deployment work; root ABA/post-last-check changes not prevented. One port, at most16 local literal endpoints; bounded supported config/launch grammar. Active rollback and unsafe owned REFRESH remain conservative refusals. No unresolved blocker for this task.
