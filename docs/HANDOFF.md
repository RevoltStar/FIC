# Current workspace

## Current base
* Branch main; base 5a16b7ddfdf75f50bc9262225bdb0e9a90304ef9. One follow-up completion commit requested; no push.

## Current task
* Fix false bulk-uninstall NOTHING_TO_RELEASE/SUCCESS for empty SYSCTL artifacts and orphan state left after recorded owner release.

## Accepted architecture / invariants
* Existing package lifecycle, daemon.lock, ownership/CAS, journal/witness and dependency contracts unchanged. No adoption, automatic orphan deletion, recovery engine, migration or provider installation. Ordinary apply/disable unchanged.
* Assignment count is not physical artifact absence. Bulk SYSCTL no-owner preflight rejects any existing managed file, including empty/header-only; final read-only SSH/SUDO/SYSCTL sweep reuses UnrecordedResourceInspection after all recorded release attempts. Active failures keep original errors/records.

## Completed / changed areas
* UninstallRollback.cpp uses strict SYSCTL no-owner proof to avoid false per-policy no-ops, then final domain proofs with phase FINAL_PHYSICAL_PROOF and summary final_physical_failed. A final orphan blocks overall ok even if per-owner release succeeded. Remnant active records preserve original failure; no false success/proof generated for them.
* UnrecordedResourceInspection.{h,cpp}: uninstall-only phase, strict artifact existence check, shared final domain sweep, same resource locks/readers/bounded inventories/current+historical paths/markers/staging. No second ownership engine. Existing default disable inspection remains unchanged.
* Unit regressions cover missing/empty/header/parameter/invalid SYSCTL files, last-owner deletion, SSH recorded A+structured orphan B, SUDO recorded A+detached wrapper B, SYSCTL recorded A+unknown B, preserved bytes/journal identities, explicit repair/retry and valid last SSH/SUDO container release.
* Native fixture adds typed SYSCTL Applied A+unrecorded B. Real rollback_all retires A, preserves B, fails final proof; explicit orphan repair permits retry. No journal reset/record retirement shortcut in fixture. Test foreign sysctl baseline equals readonly runtime and is verified unchanged/restored; active rollback still refuses a dangling foreign loader graph.
* Docs: package-lifecycle{,-validation}.md, native README and evidence/final-physical-*.json. Historical optional-provider evidence preserved; new RED uses actual 5a16b7d packages.

## Validation
* Matching affected production builds and 5 focused CTest PASS on Debian12/13 Ubuntu24/26; final rollback_executor_tests rebuilt after last valid-SSH-container regression. Four other direct test consumers build and CTest PASS on Ubuntu24.
* Four expanded real native APT gates PASS on final DEBs: optional programs absent, all 5 ELF resolve/readiness, empty/header per-policy+final refusal, mixed SYSCTL recorded release/orphan preservation, repair/retry, remove/purge and retained-active refusal. Additional four ordinary remove-from-INSTALLED/purge gates PASS, without prior manual prepare/rollback.
* Native RED with old 5a16b7d packages reproduces false ok=true for empty managed SYSCTL. Initial mixed native fixtures correctly failed on a dangling 99-sysctl.conf; test-only foreign baseline supplies valid loader graph without kernel writes. This was not a product regression or a relaxed proof.
* Shell/Python syntax and git diff --check PASS. Raw logs: build-final-release-proof/; unique native results: build-package-lifecycle/native-fic-final-proof-runtime:*. Evidence records hashes of source, archives, ELF, commands/logs and images.

## Remaining boundaries
* No task blocker. Native mixed A/B is SYSCTL; SSH/SUDO mixed cases use production backends plus deterministic command fixtures in CTest. Test-seeded journal records do not prove native provider apply.
* Targeted gates replace full upgrade/abort/override/PAM-detach repetition: package scripts/dependencies/lifecycle did not change. No full project CTest, ALT native run, live SSH, real-user PAM or hardware enforcement claim. Runtime /sys and /proc/sys readonly; existing privileged external writer/cooperative-locking boundary unchanged.
* Docker authorized; disposable runtime containers removed, images/build caches retained. No host security mutations; unrelated volumes untouched.
