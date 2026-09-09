# FIC: передача контекста

## Current base

- Ветка `main`, база: `bff13b1` (screenlock completeness + profile parsing)
  плюс corrective commit поверх него (см. git log).

## Current task

- Corrective commit: GNOME dconf accessibility при daemon `UMask=0027` —
  explicit modes для FIC-created dconf dirs, filesystem accessibility
  verification (foreign parents, profile, compiled DB), isolated child umask
  `0022` для `dconf update`, file-db path charset compatibility.

## Accepted architecture / invariants

- `fic.service UMask=0027` не определяет permissions public GNOME dconf
  artifacts: FIC-created directories (`dconf`, `dconf/profile`, `dconf/db`,
  `fic.d`, `fic.d/locks`) получают fd-based `fchmod 0755` после secure
  open+validate (openat/O_NOFOLLOW, trusted owner, no group/world write).
- Existing foreign directories НЕ chmod'ятся: только валидация (trusted
  owner, no group/world write, other-execute; `0751` достаточен, `0750`
  → fail closed «not traversable by ordinary users»).
- `verifyManagedSettings` (и ensure после `dconf update`) требуют, чтобы
  profile и compiled `/etc/dconf/db/fic` были regular, root-owned, без
  group/world write, world-readable; `0640`/`0600` → fail. Root `gsettings`
  success не считается verified при unreadable compiled DB.
- `ProcessOptions::childUmask` (fic-core, generic, optional): umask
  применяется только в child после fork, до exec; umask daemon'а никогда не
  меняется. Unset → прежнее поведение. `dconf update` передаёт `0022`;
  `gsettings` — без childUmask.
- Merge-only keyfile/locks, `DISABLE → no cleanup` (ensure с empty required
  не создаёт/chmod'ит ничего) — без изменений. Четыре screenlock keys и
  profile parser compatibility (`file-db`, whitespace, inline comments,
  fail-closed scenarios) сохранены. file-db value теперь: непустой absolute
  path без control-символов (charset не ограничен узким allowlist).

## Completed / changed areas

- `fic/src/modules/oss/desktop_environment/backends/GnomeSystemBackend.cpp`:
  fchmod 0755 для created dirs; `directoryAccessibleToOrdinaryUsers` /
  `fileAccessibleToOrdinaryUsers`; accessibility в ensure+verify;
  childUmask 0022 для dconf update; file-db charset.
- `fic-common/fic-core`: `ProcessOptions::childUmask` + применение в child.
- Tests: `GnomeSystemBackendTests` (umask-0027 regression, foreign parent
  fail-closed/no-chmod, 0751 accepted, compiled DB 0640/0600, profile 0640,
  childUmask 0022 на update, file-db charset), `ProcessOutputLimitTests`
  (child umask применён + parent umask не тронут + inherit-case),
  static checks.
- Docs: `session-agent.md`, `architecture-diagrams.md`.

## Validation

- Full build `build-fix-check` (ubuntu-24.04, systemd stub
  `/tmp/fic-systemd-stubs`) — passed.
- Relevant tests: gnome_system_backend_tests (15), screenlock_timeout_global,
  session_setting_reconciler, desktop_global_config_reconciler,
  session_aware_policy, process_output_limit (incl. child-umask cases),
  verified_process_executor, process_cancellation, both static checks —
  passed.
- Negative controls: (A) fchmod 0755 disabled → umask-тест упал; (B)
  compiled-DB readability check disabled (ensure+verify) → 0640-тест упал;
  (C) childUmask ignored → process test упал. Код восстановлен.
- Full CTest: см. финальный прогон.

## Remaining

- Live GNOME session/runtime integration не проверялась (нет disposable
  GNOME session).
- Root-only `command_hash_batch_tests` skipped.
- `dconf update` live-проверка lock semantics не выполнялась (нет dconf CLI).
