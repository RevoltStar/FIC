# FIC: передача контекста

## Current base

- Ветка `main`, исходная база текущей правки:
  `46e47841f95a9567d3868bd3cf47e33359ef2474` (GNOME system backend) плюс
  corrective commit поверх него (см. git log).

## Current task

- Corrective commit: GNOME screenlock completeness (четвёртый ключ
  `disable-lock-screen=false`) + dconf profile compatibility
  (`file-db:`, whitespace, inline `#` comments).

## Accepted architecture / invariants

- `GnomeSystemBackend` (`backendName() == "gnome"`, typed desktop `Gnome`) —
  единственный global enforcement path для GNOME; architecture contract
  (`DesktopGlobalReconcileReport`, `PolicyGlobalEnforcementResult`,
  `DesktopSystemBackend`, typed binding) не менялся.
- `screenlock_timeout` для GNOME публикует ровно четыре requirements:
  `idle-delay=uint32 N*60`, `lock-enabled=true`, `lock-delay=uint32 0`,
  `disable-lock-screen=false`. Все четыре значения и все четыре locks
  обязательны для verified (`gsettings get` exact + `gsettings writable ==
  false`). KDE/XFCE/FLY — `SessionOnly`; LXQt — `Unsupported`.
- `org.gnome.desktop.lockdown disable-lock-screen=true` не даёт GNOME Shell
  заблокировать экран, поэтому без `false` screen lock не доказуем — это
  эффективная часть существующей policy, не новая policy.
- Current-session GNOME handler (`GnomeScreenLockTimeoutHandler`) сходится
  только по всем четырём значениям; логика — header-template
  `gnome_screen_lock_timeout::applyTimeout` (compile-time DI над интерфейсом
  `GnomeBackend`, без новых runtime layers). `MandatoryGlobalRuntimeWarning`
  semantics сохранены.
- dconf profile parser поддерживает `user-db:`, `service-db:`, `system-db:`,
  `file-db:` (read-only, абсолютный путь), leading/trailing whitespace,
  inline `#` comments, blank/full-line comments. Чужие строки сохраняются
  byte-for-byte; перемещается только строка `system-db:fic` (позиция: сразу
  после первого writable-источника). Fail closed: non-writable первый
  источник (`system-db:`/`file-db:`), неизвестный тип источника, duplicate
  `system-db:fic` (в любом форматировании).
- Merge-only keyfile/locks и `DISABLE → no cleanup` сохранены; rollback и
  provenance вне scope.

## Completed / changed areas

- `fic/src/modules/oss/desktop_environment/backends/GnomeSystemBackend.cpp`:
  lockdown key в mapping + structured profile parser.
- `policies/OSS_screenlock_timeout.cpp`: четвёртая contribution.
- `policies/GnomeScreenLockTimeoutHandler.{h,cpp}`: template + lockdown key.
- Tests: `GnomeSystemBackendTests` (4-й key, verification negative cases,
  parser compatibility suite), `ScreenlockTimeoutGlobalTests` (4 keys),
  `SessionSettingReconcilerTests` (GNOME session convergence с fake backend),
  `static_checks.py.in` (fourth key, handler lockdown, file-db, no-cleanup),
  `tests/CMakeLists.txt`.
- Docs: `session-agent.md`, `architecture-diagrams.md`.

## Validation

- Fresh configure `build-fix-check` (ubuntu-24.04, PKG_CONFIG_PATH с systemd
  stub `/tmp/fic-systemd-stubs` — dev-пакета libsystemd в окружении нет) —
  passed. Full build — passed.
- Targeted: gnome_system_backend_tests, screenlock_timeout_global_tests,
  session_setting_reconciler_tests, desktop_global_config_reconciler_tests,
  session_aware_policy_tests, controlled_desktop_environments_tests,
  session_ready_validation_tests, session_ready_retry_tests,
  desktop_environment_architecture_static_checks,
  platform_profile_static_checks — все passed.
- Negative controls (все упали как ожидалось, код восстановлен): wrong
  disable-lock-screen value; writable lockdown key; удаление 4-й contribution
  (policy test + static check); удаление file-db из parser.
- Real gsettings 2.88.0 (dconf backend 0.49.0): временный профиль с
  `file-db:` принят реальным dconf runtime; `gsettings get
  org.gnome.desktop.lockdown disable-lock-screen` → `false` (ключ/схема
  существуют); `gsettings writable` → `true` без lock (ровно состояние,
  которое отвергает FIC verification). `dconf update`/компиляция db не
  выполнялись — CLI dconf в окружении не установлен. Live GNOME session
  недоступна.
- Full CTest: 82 tests, 81 passed, 1 root-only skipped, 0 failed.

## Remaining

- Live GNOME session/runtime integration не проверялась (нет disposable
  GNOME session).
- Root-only `command_hash_batch_tests` skipped.
- `dconf update` live-проверка lock semantics не выполнялась (нет dconf CLI).
