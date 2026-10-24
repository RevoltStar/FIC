# Current working state

## Current base
* `main`; integration parent `9869ae5`, boundary `534a0ad`, original task base `d8bc274`. Integration HEAD: `git log -1`. No push.

## Current task
* Debian SSH attachment `da117094-3d53-47b9-ae43-ed5a943d3347`: production integration complete and validated. Commit C contains engine/policy/unit changes; final native harness/docs/Ubuntu follow-up constitute pending commit D in the working tree. Finish D, not another implementation pass.

## Accepted architecture / invariants
* Debian12/13 strict verified apply; Ubuntu24/26 Unsupported without fallback; ALT legacy activation/compensation preserved. Shared SSH mutex and shared-file Prepared apply/disable gate.
* Configured values, bounded root-trusted foreign references and journal ownership are separate. Main SHA pinned to CAS snapshot/installed receipt. No schema/M1/fence/package changes, ownership adoption, blind restore or automatic Prepared recovery. Strict owned-value REFRESH refuses before undo/write.
* Same generic RO snapshot/restart/READY/cleanup engine; read-only publication preflight before mutation. Shared parents still require deployment-prepared private boundaries.
* Receipt binds boot/unit/full launch/input manifests+metadata/executable identity+digest/PID/invocation/proven values. Optional enabled policy values are independently proved on same protected snapshot and never gate selected policy.
* Real stock start-limit-hit fixed by conservative bounded restart budget: age unknown initial window, track own attempts; never change/reset limits. Interval0 or <=30s/burst1..1024, production admission/reference60s. External privileged restart/ABA remains outside atomic guarantees.

## Completed / changed areas
* Trusted reference builder, service/metadata caller proofs, real Ssh::apply integration, verified transaction callbacks, retained saved/unknown provenance; final-confirmation exceptions cannot retain provisional Success.
* Platform dispatch and CMake source/link dependencies; unit/contract tests for faults, ownership, shared mutex/Prepared disable, admission matrix, restart budget and platform boundaries. Updated obsolete Prepared auto-rollback expectation.
* Native module runner calls five real policy classes/real journal/sshd/systemd without daemon/fake Installed. Pending restart uses ptrace event-stop (systemd SIGCONT defeated plain SIGSTOP), then real readiness/failure/deadline. Late READY/final confirmation races, no-op/invalidation, pre-CAS/post-save/journal faults and launch overrides verified.

## Validation
* Final release native D12/13: each 30 generic +59 adapter +24 module groups PASS, exit0; unit bytes unchanged/restored sshd -t. `build-m1-evidence/ssh-release-native-debian{12,13}.log`; generated results under build-openssh-native/debian-{12,13}/evidence.
* Final full D12 build/CTest: 206 PASS/4 expected SKIP, 210 total, 174.47s, exit0; singleton/maintenance native opts enabled. `ssh-release-final-full-debian12.log`.
* Standalone provenance: all five profiles 55 PASS/0 FAIL each; Debian adds 3 real OpenSSH semantics probes each. `ssh-integrated-provenance-matrix.log`, build-ssh-provenance/<row>/native.log.
* Generic native Ubuntu24/26:202 PASS each; ALT:201 PASS/1 known stock empty-Include overlay fixture SKIP. `ssh-integrated-generic-*.log`.
* Production symbol scan: SSH save-outcome/adapter test entrypoints absent. git diff --check PASS.

## Remaining
* Commit D: native harness/Driver/CMake, documentation/validation report and separate Ubuntu socket-activation specification/TODO. Review final scope, staged diffcheck, commit, report both C/D SHA; no push.
* No full daemon/IPC/package/M1/PAM login, other kernel/VM/hardware proof. Module gate explicitly allowed by task; no synthetic Installed. ROOT kernel for containers6.6.87.2 WSL2. REFRESH/Prepared recovery remain explicit unsupported boundaries, not unfinished hidden compensation.
* M1 frozen/incomplete at task base; AGENTS §17 and maintenance docs remain authoritative. Do not resume M1 as part of SSH.

## Environment
* Docker fic-ssh-audit:{debian12,debian13,ubuntu2404,ubuntu2604,alt-p11}; native runtime private systemd PID1/no host binds/network/ports. Host SSH/PAM untouched.
* build-env-full-debian12 one writer, /src RO, /build root during run/1000 afterwards, DAC overrides dropped, QT_QPA_PLATFORM=offscreen, native singleton/maintenance env opts. No relink during CTest. Detailed reproduction/versions in pending docs/ssh-debian-verified-policy-validation.md.
