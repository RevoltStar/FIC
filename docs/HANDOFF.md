# Current workspace

## Current base
* Branch main; research task base d1b00069aa9982fea3d7a34ea11eeaabe1c3604b.

## Current task
* SSSD research R1 + R2, attachment b6926bcd. Exactly two sequential research commits, no push, no production edits. R1 is this commit; execute R2 only after committing R1.

## Accepted architecture / invariants
* Docker explicitly authorized instead of Podman. Real stock packages/systemd PID1, disposable privileged runtime, network none/loopback only, no host binds/ports/security changes. Five userlands share WSL kernel.
* Reuse existing generic engine. FIC-owned zzzz-fic.conf, per-policy keys; future offline→cache Recommended (never Required). Research does not implement adapter, policies, journal or migrations.
* Keep native config/runtime/functional and source proof levels separate; unsupported/unexecuted/inconclusive is not PASS.

## Completed / changed areas
* R1 source audit exact distro versions/patches, stock launch/input graph/reload/READY, manual RO metadata tests, actual generic engine probes, absent/stopped/activating states and barrier/checkpoint counterexamples.
* Native Debian12/13, Ubuntu24/26, ALT p11: all R1/R1_MORE/R1_ABSENT collections complete; 190 named observations in docs/sssd-native-research-evidence.json. Source hashes/line excerpts source-r1.json.
* Debian13/Ubuntu26 demonstrate existing engine snapshot+notify Success with complete safe prepared inputs. Older three rejected by stock PIDFile/trigger contract. Generic Success does not prove persistent source after cleanup: hidden late snippet/preopened FD counterexamples. No SSSD functional authentication in R1.
* Production discrepancies documented only: inactive/same-value persistent-only apply, conflicting late snippet blocks release, uncertain Prepared recovery.
* Authoritative docs: sssd-native-compatibility.md and sssd-verified-activation-design.md; scripts/README under tests/integration/sssd-research.

## Validation
* Actual generic probe build all five; native stock R1 + supplemental fixtures + absent base containers all five.
* Debian12 full project configure and CTest -R sssd_research_evidence_checks PASS 1/1. Python AST/shell syntax and evidence guard PASS; git diff --check PASS. Production unchanged, full project rebuild/CTest not rerun.
* Initial fixture EXDEV and obsolete config_file_version rejected by new validators corrected before final collections. Root-owned ALT source archive extracted/patched in container. Failed fixture runs are not SSSD results.

## Remaining / limits
* R2 still to execute: consumer/parameter defaults/ranges/domain/relations source audit, native matrix, optional local LDAP functional probe, design/evidence, second exact-title commit.
* R1 enforcing LSM, peer propagation, simultaneous enumeration, unit mutation not tested; frozen monitor restart exceeded 20s outer harness limit: deadline/cleanup INCONCLUSIVE, not PASS. One Ubuntu26 retry caught native mount interference and correctly failed; successful independent runs/checkpoints also recorded. No unconditional reliability claim.
* No native AD/IPA infrastructure; source audit must label runtime/functional gaps. Do not implement I1–I6.

## Environment
* DOCKER_CONFIG=/tmp/fic-package-docker-config; fic-sssd-research:{debian12,debian13,ubuntu2404,ubuntu2604,alt-p11}. Absent bases fic-ssh-lifecycle-native same tags. build-sssd-research/<platform> contains binaries/raw outputs/exact source. All runtime containers removed after collection.
* Full configure/CTest cache build-env-full-debian12, image fic-followup-build:debian12. Source read-only at /src, build cache /build.
