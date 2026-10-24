# Current working state

## Current base
* main. Task parent `548286e4d556dd32fc919223ccfb8bfae39a7ee4`; audit A `49ac50a47cf495f8291df6d11388e60a4f1763df`. B finalized on this base, exact title `feat(ssh): implement verified Ubuntu socket activation`. No push.

## Current task
* Ubuntu24/26 SSH verified socket activation complete. Exactly A audit + B implementation. Next direction: ALT p11 verified SSH, then installed all-distribution acceptance. M1 remains frozen.

## Accepted architecture / invariants
* Authoritative contract: docs/ubuntu-ssh-socket-activation-spec.md. Same RO engine/CAS/journal/mutex/Prepared/A-B-C-P; no package/schema/M1 changes or new engine/watcher.
* Closed Ubuntu profile: enabled active socket + inactive/active service, fixed local trigger/activation; default generic/Debian active/no-triggers contract unchanged. No product enable/start/unmask/reset-failed.
* One port, <=16 local literal endpoints; trusted generator, typed loaded/native output, actual kernel inode and PID1→sshd FD inheritance; old controlled listener gone. Receipt pins inputs/socket/generator/runtime identity.
* Missing stock /run/sshd may be created after admission/ownership/closure; unsafe existing object never repaired. Active rollback refuses. Positive offline service+socket proof permits ownership-only release, runtime NotAttempted even on failed/drifted proof; unknown/unloaded manager state refuses.

## Completed / changed areas
* service internal typed socket/profile hook + ssh/UbuntuSshSocketFlow; adapter/reference/receipt/budget; Ubuntu platform dispatch/generator trust catalog; common Ssh transaction/rollback options/wiring.
* Real native policy driver/harness and runner/CMake lists, endpoint/transaction regression tests, authoritative SSH docs/TODO. Sanitized final proof: docs/ubuntu-ssh-socket-policy-validation.json (no private key/config/reference bytes).

## Validation
* Ubuntu24/26 final real five-policy+socket matrix51 groups PASS each. Versions/image IDs/kernel/listener/FD facts and every scenario in evidence. Runtime Docker no host binds/ports/network except loopback; host SSH/PAM untouched.
* Debian12/13 OpenSSH native30 generic+59 adapter+24 module groups PASS each.
* Generic native D12/D13:201 PASS each; Ubuntu24/26:202 PASS each; ALT:201 PASS/1 SKIP. Earlier Ubuntu26 strict observer namespace-event refusal resolved by repeat, without weakening checks.
* tests/integration/ssh-provenance/run-native.sh debian12 debian13 ubuntu2404 ubuntu2604 alt-p11:55 groups each PASS after final offline diagnostic/effect fault matrix.
* Full Docker Debian12 configure/build + QT_QPA_PLATFORM=offscreen ctest:207 PASS/4 SKIP,211 total. Final logs build-env-full-debian12/ubuntu-final-{build,ctest}.log. Generic native run separately; skipped package research/PAM gates unrelated.
* Shell/Python syntax and git diff --check PASS. Full native reports build-openssh-native/<platform>/evidence; commands in runner README/spec.

## Remaining / boundaries
* No implementation blocker or unfinished Ubuntu task item. ALT and full installed daemon/IPC/package/PAM-login/VM acceptance are separate follow-ups, not claimed here.
* Common WSL2 kernel6.6.87.2; no independent VM/kernel matrix. Shared publication parents need pre-provisioned private boundaries. Root ABA/post-SUCCESS admin changes, existing strict owned-value REFRESH refusal and active socket rollback refusal remain bounds.
