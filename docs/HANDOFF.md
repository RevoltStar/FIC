# FIC handoff

## Current base

* main, dcaf521; current renderer lifecycle fixes uncommitted.

## Current task

* Fixed prelogin buttons appearing unresponsive on ALT: broker was blocked reaping a renderer it could not signal after UID drop.

## Accepted architecture / invariants

* Broker retains CAP_KILL; unprivileged renderer still drops UID and groups. Forced cleanup failure never proves successful handoff.
* Automatic five-second countdown remains universal and requires verified startup success plus renderer readiness. No PAM/security readiness relaxation.

## Completed / changed areas

* Service grants CAP_KILL. FrontendProcess checks kill errors and bounds post-SIGKILL reap instead of blocking waitpid.
* Qt uses Fusion and software cursor; initial compositor event dispatch is one pass instead of draining indefinitely. Avoids desktop style helpers and native Virtual1 hardware cursor errors.
* Added real different-UID denied-signal regression and service capability assertion. Updated prelogin README.
* Native ALT old broker stack confirmed stuck in forceReap/wait4 after renderer initialization exceeded readiness timeout.
* Installed actual production standalone optional RPM on 172.17.1.107. No active DM at replacement. New renderer readiness at 10:15:40, gate finished normally at 10:15:45, DM PID2761 active; fic/sshd active.

## Validation

* Debian12 affected targets built; ctest -R prelogin: 4/4 PASS, including denied-signal fixture as root and Qt button/confirmation callbacks. Logs build-prelogin-validation/final/input-{build,tests}.log.
* ALT production standalone build/package PASS; logs build-prelogin-validation/alt-production/input-{build,package}.log.
* PackageLifecycleTests.py PASS; git diff --check PASS. Native helper verify PASS; installed broker/frontend SHA256 match build.

## Remaining / limitations

* Physical mouse/keyboard button clicks after install not observed: native gate automatically handed off after five seconds. Offscreen callbacks tested; native readiness and normal cleanup/handoff confirmed.
* Same-version RPM replacement again returned erase failed (exit1), despite matching new binaries and loaded CAP_KILL unit. No successful RPM exit claimed.
* Remote host remains PASSIVE; no reboot performed. Prior recovery backup /root/fic-graphics-recovery-20261010. No commit/push requested.
