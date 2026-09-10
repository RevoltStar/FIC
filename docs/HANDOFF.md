# FIC: передача контекста

## Current base

- Ветка `main`.
- База до текущей правки: `17888fa` (`Исправлена ALT password-history topology`).

## Current task

- Исправить ALT p11 RPM Docker build dependency для `fic-kconfig-verifier`.

## Accepted architecture / invariants

- RPM build intentionally passes `-DFIC_BUILD_KCONFIG_VERIFIER=ON` for `fic`.
- ALT p11 `fic-kconfig-verifier` links against real KF6 ConfigCore; do not
  replace it with a stub or silently disable it in packaging.
- Current ALT KF6 Config CMake package depends on Qt6Qml, provided by
  `qt6-declarative-devel`.

## Completed

- Added `qt6-declarative-devel` to the ALT p11 RPM builder image dependencies.
- Extended desktop-environment static packaging checks to require that RPM
  Docker dependency.

## Changed areas

- `packaging/rpm/Dockerfile`.
- `tests/fic/modules/oss/desktop_environment/static_checks.py.in`.

## Validation

- `python3 -m py_compile tests/fic/modules/oss/desktop_environment/static_checks.py.in` — passed.
- `python3 tests/fic/modules/oss/desktop_environment/static_checks.py.in .` — passed.
- `git diff --check` — passed.

## Remaining

- Full `./packaging/rpm/build-fic-alt-p11-rpm-docker.sh 0.0.0-alpha` was not
  rerun after the source change.
