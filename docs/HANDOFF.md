# FIC handoff

## Current base
* Branch `main`; task base `bd9e20d4b58dcf984dd8a0bb16931dab208e7f77`.
* Commit A: `3cbc84697c66f77dc06ca5c442fc36b226e338f3` — status/admin controls.
* This snapshot accompanies commit B: `Add incident audit history and diagnostics to fic-gui`.

## Current task
* GUI Incident Response completed in two sequential commits; no next implementation stage planned.

## Accepted architecture / invariants
* GUI only uses existing administrative daemon IPC; no enforcement, recovery, PAM/FIREWALL/logind/prelogin or daemon API changes.
* Permanent incident page survives dynamic module reload/errors, including malformed module responses; selected named tabs are restored when available.
* One persistent worker serializes polling/admin/history/localization requests; polling cannot accumulate. Last valid in-memory status and acquisition timestamp survive transport/daemon/protocol failures with a prominent STALE warning above both inner tabs.
* Confirmed clear/raise never optimistically change status; every action is followed by status acquisition. Reachable DEGRADED/unproven states keep controls available while idle.
* Structured current-boot audit uses `boot_id`/`log_records`, separately from Logger and administrative IPC audit. History acquisition publishes a validated bounded batch atomically; failure retains prior events/boot/cursor/time. History transport failure also marks current status STALE; malformed individual audit lines only mark history PARTIAL.

## Completed / changed areas
* `fic-gui/src/features/incidents`: strict status parser, acquisition snapshot, worker/service, status/admin page, audit parser/table/filter/history service/view.
* MainWindow, shared GUI localization and embedded RU/EN fallback; daemon language resources; GUI README; GUI mock/offscreen tests and tests CMake.
* History handles pagination/incremental updates, replay deduplication, cursor expiry/rotation, boot changes, partial/truncated input and stale cache. Only available audit fields are shown as PlainText.

## Validation
* Native Qt5: full build passed with `FIC_TARGET_PLATFORM=ubuntu-24.04` (host runtime is ALT p11; not an Ubuntu runtime claim). Related CTest 10/10 passed; RU/EN ownership/localization static guard covers 52 keys. Native full CTest: 163 PASS, 11 FAIL, 4 SKIP due sandbox/root/NSS/fixture environment; not a clean native full-suite result.
* Docker CLI through a temporary rootless Podman-compatible API (no Docker daemon available), existing `localhost/fic-quarantine-test:debian12` image; source mounted read-only, network disabled, `DAC_OVERRIDE`/`DAC_READ_SEARCH` dropped for permission fault injection.
* `cmake -S /src -B /build -DFIC_TARGET_PLATFORM=debian-12`; full `cmake --build /build -j2` PASS; full CTest **178/178 PASS**, 37.12 s, Qt6. Initial run with DAC override: 177/178, permission fault injection bypassed by root; no unrelated code changes made.
* CMake language installation and Debian/RPM component staging inspected; new strings follow existing language install flow and are embedded in GUI resources.
* `git diff --check` PASS. Evidence: ignored `build-incident-docker/{final-configure,final-build,final-ctest}.log`; native logs `/tmp/fic-incident-native-complete-*` and `/tmp/fic-incident-full-*`.

## Remaining / limits
* No implementation components unfinished. Real graphical desktop/live daemon incident operations and physical containment intentionally not tested; GUI uses mock IPC in offscreen tests.
* History is bounded: 200 records/page, 4 pages/batch, 1000 cached events/4 MiB accounted event data, 16 KiB raw lines. Missing/rotated/evicted data is marked PARTIAL; no all-boots archive.
* Existing log_records has no physical record ID: SHA-256(file path + raw line) coalesces fully identical lines from the same file. No new IPC endpoint or persistent GUI cache.
* Closing a page safely waits for its current shared-client request (30 s timeout), then interrupts remaining work. Temporary test containers are removed; original images/containers remain untouched.
