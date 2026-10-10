# FIC handoff

## Current base

* `main`, `8cc07ea64cfd1ba4e8ed3bf79a7153ea100692e4`; current prelogin fixes uncommitted.

## Current task

* Completed requested ALT-only xgrp frontend access and visible five-second automatic handoff countdown. No additional cleanup/refactor requested.

## Accepted architecture / invariants

* Gate is systemd/UI only; no authentication or direct DM start. Manual/power actions remain immediate and cleanup still requires renderer reap, VT restore and cgroup proof.
* Auto countdown begins only with verified current-boot startup success/readiness and renderer-ready. Monotonic clock; loss of eligibility or daemon PID change resets it. Status rechecked before exit; countdown is never readiness proof.
* Existing private view schema unchanged: countdown text uses startup field; also shown on text VT.
* ALT target adds xgrp to clamped video/render/input groups. Root/fic administrative groups remain excluded. Other targets do not add xgrp.

## Changed areas / completed

* fic-prelogin CMake/generated graphics paths, FrontendProcess, controller, console rendering, README; controller regression tests use injected clock.
* RPM built for installed version 0.0.0~aplha-1.altp11 and installed on 172.17.1.107; current LightDM PID1747 unchanged, fic/sshd active. UID495 with matching groups971/972/973/977 passes DRM R/W access check without opening device/changing VT.
* Remote host remains configured PASSIVE. Earlier remote repairs restored missing DAC values and ALT PAM topology via maintenance managers; those were not repository source changes.

## Validation

* Debian12 configure/build affected targets + prelogin CTest: 4/4 PASS. Full incremental build and CTest excluding unchanged root-sensitive mutation_journal_tests: 170/170 PASS. Logs build-prelogin-validation/final/countdown-*.log.
* ALT configure/build broker/frontend/integration/controller/Qt tests PASS; optional RPM build PASS. Generated ALT_XGRP true on ALT, false on Debian. Logs build-prelogin-validation/cross/altp11/countdown-*.log.
* Controller checks five-second boundary, countdown reset on daemon loss/PID/renderer change, immediate manual handoff, mode/severity eligibility. git diff --check PASS.
* Native installed helper verify PASS; broker hash matches ALT build, one current RPM record; device permission check with frontend identity PASS. No DM restart or host reboot performed.

## Remaining / limitations

* Full graphical startup/countdown/handoff on ALT awaits next boot; only device permission checked live. Current user desktop was preserved.
* RPM --replacepkgs returned erase failed for same-version reinstall although new files/metadata installed. One current package record, correct new broker hash and helper integration verified; do not describe RPM command as exit0.
* Remote backup /root/fic-prelogin-recovery-20261010-countdown. Ignore build/VM assets. No source commit/push requested for this task.
