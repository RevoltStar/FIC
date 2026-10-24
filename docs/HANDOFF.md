# Current working state

## Current base
* main, parent `f625f285c67681693703946df33725baa0d05420` (Ubuntu verified complete). No push.

## Current task
* Attachment9b40fb0b: ALT p11 SSH verified activation, exactly A audit + B production. A native audit complete; commit `test(ssh): establish ALT p11 native activation contract`, then autonomously B. Do not stop at checkpoint/A.

## Accepted architecture / invariants
* Authoritative docs/alt-p11-ssh-verified-activation.md. Native stock ALT Type=simple/NotifyAccess=none, sshd.service, root foreground -D $EXTRAOPTIONS, required /etc/sysconfig/sshd. Pre: ssh-keygen -A then sshd -t. No socket units/triggers; own listeners, not Ubuntu FD inheritance.
* Same generic RO engine, closed ALT readiness predicate (new inv/PID/exe, exact native kernel listeners/old inode absence + SSH banner); bounded loops, no sd_notify/new engine/watcher. Debian/Ubuntu default contracts unchanged. No M1/packaging/schema changes.
* Stock /etc/openssh/sshd_config has no Include; systemd places external symlink in unowned sshd_config.d, unused by stock main. Do NOT auto-capture/create that .d. Optional existing administrator tree sshd_config.local.d confirmed native; FIC never creates/includes it automatically. Main/env/all3 stock HostKey pairs required, -A under RO must be no-op. Missing/unsafe key refuses before save.
* Strict enabled/ready apply admission; no fallback/hidden enable/start/unmask/reset-failed. Existing mutex/Prepared/CAS/durable save/provenance/receipt retained. Active rollback may conservatively refuse; proven offline ownership-only release must not claim runtime activation.

## Completed / changed areas
* tests/integration/ssh-alt-p11-research: guarded runner/research/28-case sanitized evidence, README. docs ALT contract and root CTest safe guard only. Production unchanged in A.
* Native actual ALT openssh-server/common9.6p1-alt7, systemd258.9-alt1; image sha256:1da25ea4959352bc9aa4d070beba18eb990673f3d5a261a06e659c5ddfdd1661. RPM main/env/unit verify clean. No host SSH/PAM/network touched.
* Native defaults UsePAM=yes, Pubkey=yes, root without-password (existing normalizer), tries6/Port22, RSA/ECDSA/ED25519 defaults under /etc/openssh. Binary uses libpam_userpass; RPM source/changelog captured, no full source audit claim.
* Native restarts/new inode identity, all5 values, -T/-C, Include recursion/relative base, selected Match, EXTRAOPTIONS f/o/p, RO source-vs-oldFD persistent change, enabled/inactive/disabled/failed/masked, ptrace pending and auto-restart observed. Stock keys absent before first unit start cause -T/-t failure; stock Pre -A initializes them.

## Validation
* bash tests/integration/ssh-alt-p11-research/run-native.sh fic-ssh-audit:alt-p11:28 cases PASS; report build-alt-ssh-research/alt-p11/report.json and journal/container.json. Guard --self-test PASS; bash -n PASS; git diff --check PASS. Root CTest alt_p11_ssh_research_guard PASS (Docker D12 configure + targeted CTest).
* Shared WSL2 kernel6.6.87.2, no independent VM/kernel or full installed FIC/PAM-login acceptance.

## Remaining / next
* Commit A after guard CTest, then implement B per authoritative plan. Narrow simple-profile engine readiness; parameterize paths/env/optional admin tree/default keys; shared listener helper reused from Ubuntu; ALT dispatch/no legacy fallback; receipt/listener proof; offline release profile/active refusal.
* Native real policy ALT cases including stock config without manual simplification, then all5 generic/provenance, D12/13 module+adapter, U24/26 socket51 regressions, full D12 build/CTest. Add/update related unit/CI; final evidence/docs/TODO/HANDOFF; commit B `feat(ssh): implement verified ALT p11 activation`. No push, exactly2 commits if no objective blocker.
* Existing private mount-boundary deployment, root ABA, strict owned-value REFRESH refusal stay bounds. Do not begin another hardening phase after ALT; next task installed VM/all-distro acceptance.
