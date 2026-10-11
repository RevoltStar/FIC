# FIC handoff

## Current base
* main. Original task base `e279c46eb79335b624ac3e00559d051dcd1526bb`.
* DE commit `521599b07bd1cb924b345c474fee98a3cf7d37f6`: `Implement transactional DE scope reconciliation and ownership-safe rollback`.
* This snapshot accompanies the second/final task commit: `Add controlled display manager scope and rollback-safe autologin enforcement`.

## Current task
* DE/DM transactional scope implementation complete within the accepted native persistent/live runtime boundary. No next refactor or migration planned.

## Accepted invariants
* Configured intent saves/reloads without protected reconciliation; independent scope/de and scope/dm checkpoints share MutationJournal. Only matching Applied/committed scope authorizes Required consumers; logical scope grants no physical ownership.
* Exact owned delta/block/artifact rollback, no foreign whole-file snapshots or legacy adoption. Unknown policy/action/route fails closed. Root CAS + FIC locks retain the documented residual race against unrelated writers.
* No automatic DM restart. User accepted native persistent verification as SUCCESS, with live_runtime=NOT_VERIFIED separately visible in apply message/verification and startup audit, independent of log filtering.
* KDE/XFCE atomic setters remain unavailable/fail-closed; FLY persistent inverse exists but runtime enforcement refuses unproven effectiveness.

## Completed
* DM typed SDDM/GDM/LIGHTDM scope, installed/selected/running inventory, known executable identity/custom-route refusal, observational compliance, Required/reverse guards.
* Coordinator preflights all targets/releases, prepares, ensures/releases, verifies actual Applied ownership and resolved release, then rechecks inventory/config versions before commit. Direct ban apply is read-only/guarded.
* DM journal stores fixed manager/route/seats/separator/creation inode/hadApplied/phase. Exact ID block release preserves foreign bytes and transferred files. Prepared-before-publication, native/fsync-before-Applied, interrupted release completes before new identity enrollment. Huge route wraparound and corrupt load/status/refresh rejected.
* Native SDDM tokenizer/version, GDM GKeyFile/runtime flags and LightDM --show-config/source/seat checks. Actual compiled distro paths fixed: ALT SDDM /etc/X11/sddm/sddm.conf + /usr/share/sddm/conf.d; GDM /var/run/gdm/custom.conf. Read-only stock root-owned /var/run -> /run alias explicitly re-proved; mutation symlink refusal unchanged. Inputs re-proved after native inspection.
* Joint rollback/package preflight+release before PAM detach. Generated DEB/RPM failure gates preserve foreign state. Old unchecked DM writers removed.
* Scope/journal/daemon/platform/default/localization/CMake/packaging tests and authoritative docs updated. Detailed matrix/report: docs/graphical-scope-validation.md; contract: docs/graphical-scope-transactions.md.

## Validation
* Full configure/build Debian12 builder fic-deb-builder:debian12-final PASS. Final build dm-evidence/dm-alt-route-build.log.
* Full CTest after final ALT/input-drift fixes **174/174 PASS**, 71.57s, dm-evidence/dm-alt-routes-ctest.log. Drops DAC_OVERRIDE/DAC_READ_SEARCH; Git safe.directory=/src. Includes package, PAM, prelogin, journal and rollback checks. git diff --check PASS; native gate shell syntax PASS.
* Native persistent DM loaders + restart/release/foreign settings PASS on five real distro images/packages:
  * Debian12: sddm0.19.0-5, gdm3 43.0-3, lightdm1.26.0-8.
  * Debian13: sddm0.21.0+git20250502.4fe234b-2, gdm3 48.0-2, lightdm1.32.0-6+b2.
  * Ubuntu24: sddm0.20.0-2ubuntu4.2, gdm3 46.2-1ubuntu1~24.04.9, lightdm1.30.0-0ubuntu14.
  * Ubuntu26: sddm0.21.0+git20250502.4fe234b-2ubuntu3, gdm3 50.1-0ubuntu0.1, lightdm1.32.0-6ubuntu4.
  * ALT p11: sddm0.21.0-alt3, gdm48.0-alt5, lightdm1.32.0-alt15, Qt6-devel6.11.2-alt1. Final native-alt-routes-final.log; also negative runtime alias test.
* Evidence under ignored build-prelogin-validation/dm-evidence. Network HTTP failures resolved via official HTTPS/cache with hashes/signatures retained; approval timeouts were infrastructure, eventually allowed. No host /etc or remote policy mutation.
* DE committed evidence: full build +173 CTest and native GNOME Debian12/13 Ubuntu24/26 PASS. ALT native DE was not verified in that pass.

## Remaining / limits
* No unfinished implementation components.
* Live DM runtime, GNOME Shell/FLY/KDE/XFCE sessions and actual FIC package-manager install/erase NOT VERIFIED. Native loaders/backend release and generated removal hooks are distinct evidence.
* Root CAS/locking residual race remains as accepted; no claim of atomic exclusion against unrelated root writers.
