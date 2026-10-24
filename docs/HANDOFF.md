# Current working state

## Current base
* `main`; production integration `b978f2c07475d6ef6ec5e8613b5239f6052def67`; final native/docs completion follows in HEAD (`git log -1`). Earlier profile/admission `9869ae5`, boundary `534a0ad`, original task base `d8bc274`. No push.

## Current task
* Debian SSH attachment `da117094-3d53-47b9-ae43-ed5a943d3347` completed within its accepted module/systemd/OpenSSH boundary. No unfinished Debian implementation. Ubuntu socket activation is a separate future task, not started.

## Accepted architecture / invariants
* Debian12/13 strict verified policy apply; Ubuntu24/26 Unsupported without fallback. ALT legacy activation/compensation retained; common SSH mutex/Prepared gate protects apply/disable across policies.
* Desired values, root-trusted foreign references and journal ownership remain separate. Main expected SHA is pinned to CAS snapshot/installed receipt. No schema, M1/fence/package changes, ownership adoption, blind restore or automatic Prepared recovery. Strict owned-value REFRESH explicitly refuses before undo/write.
* Existing generic engine performs RO snapshot/restart/READY/cleanup; shared read-only publication preflight runs before persistent mutation. Shared parents still require separately prepared private boundaries.
* Single bounded in-memory receipt binds boot/unit/full launch/inputs+metadata/executable identity+digest/PID/invocation/proven values. Optional enabled values enter only after independent proof on same protected snapshot; optional failures do not gate selected policy.
* Stock start-limit-hit was reproduced and fixed by bounded own restart budget, without reset/changing limits. Age unknown initial window, then rolling attempts; interval0 or <=30s/burst1..1024, production admission/reference60s. External privileged restart/ABA remains outside atomic guarantees.

## Completed / changed areas
* Real Ssh::apply integration, reference builder/caller proofs, verified transaction callbacks, saved/unknown provenance, shared mutex and cross-policy Prepared disable gate, platform dispatch and build dependencies.
* Native module runner uses actual five policy classes/journal/sshd/systemd, without fake Installed or daemon startup bypass. Real pending lifecycle uses test-only ptrace barrier; late confirmation exceptions cannot retain provisional Success. Native Unknown and NonCompliant diagnostics are distinct.
* Authoritative contract: docs/ssh-verified-activation-adapter.md; validation/reproduction: docs/ssh-debian-verified-policy-validation.md. Future Ubuntu task: docs/ubuntu-ssh-socket-activation-spec.md (also TODO).

## Validation
* Final native Debian12/13: each 30 generic experiments +59 adapter cases +24 module groups PASS, exit0; new PID/invocation/listener/no-op, pending ready/failure/deadline, late runtime/enablement, unsupported launch and post-save/journal faults. Vendor unit bytes unchanged/restored sshd -t.
* Final full D12 build/CTest: 206 PASS/4 expected SKIP, 210 total, 174.47s, exit0; singleton/maintenance native opts enabled. Skips documented in validation report.
* Standalone provenance all five profiles: 55 PASS/0 FAIL each; Debian adds3 real OpenSSH semantics probes each.
* Generic native Ubuntu24/26:202 PASS each; ALT:201 PASS/1 known stock empty-Include overlay fixture SKIP.
* Production symbol scan: SSH save-outcome/adapter test entrypoints absent. git diff --check PASS; final harness self-test PASS.
* Detailed ignored logs: build-m1-evidence/ssh-release-{native-debian12,native-debian13,final-full-debian12}.log, ssh-integrated-provenance-matrix.log, ssh-integrated-generic-*.log; sanitized native evidence under build-openssh-native/debian-{12,13}/evidence.

## Boundaries / next work
* No full daemon/IPC/package/M1/PAM login or other kernel/VM/hardware proof. Module gate explicitly allowed by task. Containers share kernel6.6.87.2 WSL2. This does not claim continuous enforcement or arbitrary privileged ABA protection.
* REFRESH/semantic Prepared recovery and wrapper-body fingerprint follow-up remain explicit known boundaries, not hidden compensation. Ubuntu implementation requires a new task; ALT not declared verified.
* M1 remains frozen/incomplete at original task base; AGENTS §17 and maintenance design docs unchanged. Do not resume M1 automatically.

## Environment
* Docker fic-ssh-audit:{debian12,debian13,ubuntu2404,ubuntu2604,alt-p11}; native runtime systemd PID1/private namespaces/no host binds/network/ports. Host SSH/PAM untouched.
* build-env-full-debian12 one writer, /src RO, /build root during run/1000 afterwards, DAC overrides dropped, QT_QPA_PLATFORM=offscreen, native singleton/maintenance opts. No relink during CTest.
