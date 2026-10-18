# Current working state

## Current base
* `main`, `1e638d2938f1aebf53df5ca604fe71028340af8e`; initially clean. One usr-merge implementation commit requested, no push.

## Current task
* Completed safe usr-merge support for unit fragment/drop-in provenance only; one completion commit over the base, no push.

## Accepted architecture / invariants
* Only root-owned `/lib -> usr/lib` or `/lib -> /usr/lib` for paths under `/lib/systemd/system/`; no other symlink exceptions. Ordinary no-symlink paths retained.
* Descriptor-rooted O_NOFOLLOW traversal, alias target from readlinkat on pinned O_PATH FD; trusted root/directories, regular root-controlled final file; statx mount identity required. Keep all chain FDs through capture and repeat traversal after hashing.
* Fingerprint pins original/canonical paths, chain mount/dev/inode/UID/GID/mode, alias target/mtime/ctime, final metadata/SHA. Directory timestamps intentionally excluded; hidden privileged ABA between checks remains outside guarantee.
* Generic openAbsolute, EnvironmentFile, namespaces, propagation, readiness, cleanup, public API, SSH policies, ownership, apply/rollback/MutationJournal unchanged. No policy integration or host/stock SSH mutation.

## Completed / changed areas
* VerifiedConfigLaunchContract.{cpp,h}: narrow unit-source reader, bounded cumulative budget, repeat identity/metadata capture; initial UnsupportedConfiguration / observed changes InterferenceDetected through existing SystemdActivation checks.
* VerifiedConfigServiceTests.cpp: grammar/identity fail-closed. NativeTests.cpp: isolated descriptor-root filesystem positive/negative/race suite, read-only stock SSH reader, vendor notify full activation and post-preflight same-SHA replacement.
* Debian12 actual stock and fixture FragmentPath are /lib/systemd/system/{ssh,fic-vcsa-test}.service; other platforms use /usr/lib. Stock validate still refuses uncovered EnvironmentFiles (Ubuntu triggers).
* Native stock probe RefUnit uses system bus to retain inactive unit without starting it; production reader still direct root PID1.
* Component contract/security review updated; historical native audit preserved with follow-up note.

## Validation
* Final native matrix logs `build-verified-config/logs/*-usrmerge-public.log`: Debian12/13, Ubuntu24.04/26.04, ALT all 132 PASS / 0 FAIL / 0 SKIP. All earlier 91 regressions retained.
* Vendor fixture directly calls public activate(), asserting new InvocationID/READY/no cleanup errors/no residuals. All five runs exit 0; existing 91 regressions plus 41 new checks per platform.
* Full Debian12 configure/build + CTest: 186 PASS / 0 FAIL / 1 expected native opt-in SKIP, 187 total (161.79s); log `full-debian12-usrmerge-final.log`. Unit contract PASS; privileged native evidence comes from the separate five-platform runs.
* Full build uses Docker fic-ssh-audit:debian12, source RO, build-env-full-debian12 volume, no network, -j6, QT_QPA_PLATFORM=offscreen; drops DAC_OVERRIDE/DAC_READ_SEARCH for real chmod negative tests, safe.directory=/src only inside container. Build-root ownership restored via trap.
* Interim Ubuntu26 refused a mount event; final fresh containers pass without weakened observer/assertions. No production retry added.
* Final native test target rebuilt after last harness-only assertion edit; related CTest: unit PASS, native expected opt-in SKIP (`debian12-usrmerge-final-target.log`). git diff --check PASS; diff limited to seven allowed source/test/doc files.
* All userspaces share 6.6.87.2-microsoft-standard-WSL2; no independent kernel/VM or enforcing SELinux coverage.

## Remaining
* Requested implementation and validation complete. No pending implementation work.
* No stock SSH restart, host mounts, real VM/kernel matrix or production policy integration tested/attempted. Existing privileged ABA/observer limitations retained and documented.
