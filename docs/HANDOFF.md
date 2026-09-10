# FIC: передача контекста

## Current base

- Ветка `main`; corrective commit поверх `0b500a5` (актуальный SHA см. в
  `git log -1`).

## Current task

- Исправлена неполная ordinary-user accessibility verification для GNOME
  system dconf и race-семантика `mkdirat(...)=EEXIST`.

## Accepted architecture / invariants

- `GnomeSystemBackend` проверяет через fd всю directory chain от
  `trustedRoot` до parent каждого public dconf artifact: trusted owner, no
  group/world write, `S_IXOTH` на каждом компоненте, `openat/O_NOFOLLOW`.
- Existing foreign ancestor с `0750` приводит к fail closed и не chmod'ится;
  `0751` допустим. FIC-created directory получает `0755` только если
  `mkdirat` реально завершился успешно.
- `mkdirat(...)=EEXIST` означает raced-in existing foreign state: объект
  secure-open/validate, но не `fchmod`.
- Profile и compiled DB остаются regular, trusted-owned, safe и
  world-readable. Четыре GNOME screenlock keys, merge-only semantics,
  `DISABLE -> no cleanup`, current-session convergence и profile parser не
  менялись.
- `dconf update` по-прежнему получает child-only umask `0022`; parent umask и
  `fic.service UMask=0027` не менялись.

## Completed / changed areas

- `GnomeSystemBackend.cpp`: reusable secure ordinary-traversal mode в
  `openDirectory`, full-chain helper `pathTraversableByOrdinaryUsers`, safe
  `EEXIST` handling.
- `GnomeSystemBackendTests.cpp`: hidden intermediate ancestor для ensure и
  verify, positive `0751`, late permission regression.
- Релевантные описания обновлены в `session-agent.md` и
  `architecture-diagrams.md`.

## Validation

- Configure существующего `build-check` (`ubuntu-24.04`) — passed после
  восстановления временного `/tmp/fic-systemd-dev/include` stub path.
- Targeted build: `gnome_system_backend_tests`,
  `screenlock_timeout_global_tests` — passed.
- Targeted CTest: 8/8 passed (`gnome_system_backend`, screenlock global,
  reconcilers, session-aware policy, process output limit, architecture and
  platform static checks).
- Negative control без `S_IXOTH`: `gnome_system_backend_tests` ожидаемо упал;
  после восстановления fix снова passed. Positive `0751` и late-regression
  cases passed в основном прогоне.
- Полная сборка проекта НЕ запускалась по явному ограничению задачи.
- Full CTest не запускался: существующий tree не был полностью собран.

## Remaining

- Live GNOME session/runtime integration не выполнялась.
- Deterministic syscall injection для узкого `ENOENT -> mkdirat EEXIST` race не
  добавлялся; production branch исправлен и документирован без крупного seam.
