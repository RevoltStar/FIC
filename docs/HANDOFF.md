# FIC handoff

## Current base

* Branch: main; HEAD `f6b8a4745e91646ba83f4042d343700de41ab21a` (completed DC new/all lifecycle).

## Current task

* Completed: increase prelogin renderer readiness timeout from 15 to 60 seconds for all distributions.

## Accepted architecture / invariants

* Only renderer startup wait changes; five-second DE handoff countdown and existing cleanup/fallback behavior remain separate.
* Remote ALT VM uses Bochs DRM and LLVMpipe; a cold boot with diagnostic 60-second binary reached renderer readiness 32.95 seconds after DRM selection, 36.81 seconds after service start. Remote PAM startup errors are separate.

## Completed / changed areas

* `fic-prelogin/src/main.cpp`: readiness timeout 60 seconds.
* `fic-prelogin/README.md`: documented timeout and common distribution behavior.

## Validation

* Debian12 Docker environment (`fic-deb-builder:debian12-final`): `cmake --build /build --target fic-prelogin -j2` PASS.
* `ctest --test-dir /build -R "^prelogin_.*tests$" --output-on-failure`: 4/4 PASS (controller, frontend process, Qt view, package lifecycle).
* Local legacy `build-check` has no fic-prelogin target; validation used existing container build instead.
* `git diff --check` PASS.

## Remaining / limits

* Source-built binary not deployed to remote machine. Remote machine retains temporary diagnostic binary with 60-second limit; original in `/var/tmp/fic-prelogin-diagnosis/fic-prelogin.original`. Package reinstall replaces that temporary change.
* Cold-boot runtime evidence used diagnostic patched installed binary, not this source build. Hardware/full distro matrix not rerun for this timeout-only change.
* Remote startup PAM errors and cleanup message hiding original fallback cause remain outside this task.
