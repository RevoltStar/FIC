# Current workspace

## Current base
* Branch main. A: 621910c (PAM domain classification and native retry). B is the accompanying final DEB runtime/provider validation commit. Earlier bases: ab0f47e strict dependency discovery; 752354c lifecycle; 50e0d04 historical rich-image gates. No push.

## Current task
* Attachment68cebd90 follow-up completed: silent skip fixed; real before/partial infrastructure detach retry proved; final real DEBs install/remove/purge in minimal Debian12/13 and Ubuntu24/26. No next development stage authorized.

## Accepted architecture / invariants
* AGENTS17/docs/package-lifecycle.md unchanged: four states, daemon-owned policy release, infrastructure-only helper, daemon.lock, ownership/CAS/journal guarantees. No M1/runtime/finalizer/cancel/automatic restart/adoption.
* Supported/NotApplicable/Error: only resolved native ALT passwdqc/static + pwhistory/TCB excludes C2. Missing capability/scope or unexpected topology is a FAILED PAM_PASSWORD JSON outcome.
* DEB needs actual ELF dependencies plus sudo/procps/openssh-server for existing uninstall inspections. OpenSSH installation/activation follows distro rules; SSH release restrictions unchanged.

## Completed / changed areas
* A daemon support classification, explicit JSON failure, unit/RED-GREEN and detach_retry_native.py. Real prerm failures after rollback/stop preserve UNINSTALLING/main payload/referenced PAM module; partial auth detach is real. Explicit obstruction repair + restricted interval1 restart/idempotent rollback and normal remove/purge pass, without restoring resources/config values. Manual commands are in docs/package-lifecycle.md.
* B declares missing non-ELF providers, updates dependency regression and supplies separate minimal runtime Dockerfile/init/preparation/driver. Runtime fixture uses readonly /sys and /proc/sys BEFORE PID1, masks coldplug, allows native udev control/inventory via test-only condition overrides. No production unit is changed; this does not validate hardware enforcement.
* All four final runtime gates PASS: APT actual Depends, no preinstalled Qt/devel, all 5 shipped ELF ldd, installed statuses/audit, both daemons, CLI/readiness, main remove, surviving helper proof, purge. Final retry rerun PASS in minimal Ubuntu24 on final archives.
* Docs and compact evidence: docs/package-lifecycle-validation.md and tests/integration/package-lifecycle/evidence/followup-*.json. Archive/builder/ELF hashes, independent image identities, actual outputs/failures included. Native README gives reproduction commands.

## Validation
* Native affected builds + 9 related CTest PASS on Debian12, Debian13, Ubuntu24, Ubuntu26; final packaging fix repack + 5 related CTest PASS per platform. Support regression rejects original logic (bool→enum adaptation only), fixed code GREEN; provider regression rejects previous Depends, fixed code GREEN.
* Four real minimal APT install/readiness/remove/purge gates and final detach retry PASS. Bash/Python syntax/related static checks and git diff --check PASS. No new full project build/CTest claim.
* Raw logs/evidence: build-package-followup/, build-package-lifecycle/native-* referenced by committed evidence. Current DEBs: build-env-full-debian12/followup-packages and build-recovery-policy/{debian13,ubuntu2404,ubuntu2604}/followup-packages.

## Remaining boundaries
* No unresolved blocker for this follow-up. Initial udev-condition failures were a harness defect; missing sudo/SSH/sysctl prerequisites were packaging defects and fixed. Old three readiness-timeout root cause remains unproved; 30s limit untouched. No real-user PAM authentication, physical devices, graphical boot, live SSH continuity or physical reboot claim.
* Podman absent, Docker used by existing user authorization. Disposable runtime containers are removed by runner; build/runtime images/caches retained for reproduction. Preserve unrelated six volumes. DOCKER_CONFIG=/tmp/fic-package-docker-config avoids missing Windows credential helper.
