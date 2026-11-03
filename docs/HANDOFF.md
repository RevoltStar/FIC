# Current workspace

## Current base
* Branch main; task base `96b88d2b40abff5cec9cd4352891401350e26719`.

## Current task
* Attachment3169bd67: initially compliant enabled SSH apply must establish proven FIC ownership. Requested single commit: `feat(ssh): establish ownership for initially compliant policies`; no push.

## Accepted architecture / completed
* Foreign compliance follows existing Prepared → CAS/durable write → verified activation → Applied. Only exact Applied owner/value/block/provenance can use the no-write reapply path. Missing owned block and empty orphan container refuse; no adoption/recreation.
* Strict Port contract retained: unsupported prospective own Port with matching Included Port refuses before Prepared/write. Includes untouched; no endpoint normalization or multi-file wrappers. Scalars remain supported with matching foreign values.
* Existing REFRESH/release, schema3/schema2 and ID-only legacy contracts retained. Legacy wrappers without fingerprints refuse REFRESH; historical fingerprints are never synthesized. Legacy release limitations remain documented.
* EOF is current foreign snapshot framing. SSH serialization preserves final-LF presence; apply and release planning copy the pinned snapshot. FileHandler exposes virtual pendingContent; its default implementation and non-SSH serializers are unchanged. No new journal fields/recovery.
* Production: Ssh.cpp, SshConfigFile.{h,cpp}, SshRollback.cpp, shared FileHandler.h. Native fixture links missing current RollbackExecutor dependencies; no SSSD behavior changed.
* Unit/native assertions cover all five initial owned applies, exact journal payload, Port wrapper fingerprints, repeat no-write/inode stability, REFRESH, active/offline release, byte-exact no-LF restoration, orphan/missing ownership and journal faults. Existing platform/legacy assertions updated; no new framework.

## Validation
* Final full project build PASS: build-sssd-i1/full/ssh-owned-completion-build.log.
* Final full CTest: 216 PASS, 1 FAIL, 4 opt-in SKIP / 221, 180.61s; ssh-owned-completion-ctest.log. Only failure: sssd_i6_evidence_checks intentionally detects changed production source hashes. Historical SSSD reports not relabeled, guard not weakened; five-platform SSSD matrix not rerun. Skips: generic native activator, daemon singleton, maintenance preflight, package PAM hooks.
* Current native ownership group: ALL FIVE Debian12/13, Ubuntu24.04/26.04 and ALT p11 PASS, 9 cases/43 operations each, real OpenSSH/systemd. ALT rerun completed after reboot. Includes pre-Prepared refusal and no-LF active/offline release. Concise source-bound evidence: tests/integration/verified_config_service/openssh_native/evidence/ownership-lifecycle.json.
* Current real Debian12 packages + installed daemon/CLI PASS: build-ssh-lifecycle/remote-debian-12-20261102T191632Z-56281/ssh-remote-results.json. Foreign Pubkey=yes gets ownership; repeat/disable preserve bytes without final LF; verified refresh/uninstall/remove/purge and existing authenticated TCP survive. Package builds under build-ssh-owned-package/debian-12/lifecycle-packages.
* Source/harness manifests at build-ssh-owned-validation verified unchanged after reboot. Python syntax, shell syntax and git diff --check PASS.
* Supplemental pre-EOF runs: REFRESH21 and Match12 all5 PASS; release30 four Debian/Ubuntu PASS; ALT positive release5 PASS and default65 PASS. Full ALT negative release stopped, not PASS. These older binaries are supplemental, not final-source evidence.

## Remaining
* Required SSH acceptance completed. This change set is the single requested completion commit; no push.
* No host SSH/security mutations; tests only disposable Docker fixtures. No automatic provider install/start, no new lifecycle/schema/recovery, no generic activator changes. Full CTest remains explicitly non-green due stale unrelated SSSD evidence.
