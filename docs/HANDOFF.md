# FIC: передача контекста

## Current base

- Ветка `main`.
- База до текущего commit: `2433ae9`.

## Current task

- Перевести FLY `screenlock_timeout` в `MandatoryGlobal` через системный
  `theme.master` и исключить root-доступ к пользовательскому `current.themerc`.

## Accepted architecture / invariants

- GNOME и FLY — `MandatoryGlobal`; KDE и XFCE — `SessionOnly`; LXQt —
  `Unsupported`.
- FLY persistent authority —
  `/usr/share/fly-wm/theme.master/themerc`, секция `[Variables]`.
- `FlySystemBackend` — единственный persistent FLY enforcement/proof path;
  `FlyBackend` выполняет только session-scoped `fly-wmfunc` runtime calls.
- `DISABLE` не удаляет и не откатывает сохранённые settings.

## Completed

- Добавлен secure merge/verify `FlySystemBackend` с полной fd-relative
  ancestor/file validation, atomic replace и fail-closed semantics.
- `screenlock_timeout` публикует три independent FLY requirements и считает
  FLY `MandatoryGlobal`; production reconciler регистрирует backend `fly`.
- Из `FlyBackend` удалены чтение и запись `~/.fly/theme/current.themerc` и
  неиспользуемый `getValue`; handler выполняет три runtime updates без readback.
- Добавлены backend, policy/reconciler, session и static security regressions;
  выполнены пять требуемых negative controls с последующим восстановлением.

## Changed areas

- FLY system/session backends и `OSS_screenlock_timeout`.
- Production desktop backend composition.
- Desktop backend/policy/session/static tests.
- Desktop architecture и session-agent documentation.

## Validation

- Targeted build: `fly_system_backend_tests`,
  `screenlock_timeout_global_tests`, `session_setting_reconciler_tests`,
  `desktop_global_config_reconciler_tests`, `session_aware_policy_tests`,
  `gnome_system_backend_tests` — passed.
- Targeted CTest: 8/8 passed, включая platform и desktop-environment static
  checks, GNOME regression и все новые FLY tests.
- Negative controls поймали: FLY `SessionOnly`, потерю FLY contribution,
  возврат `current.themerc`, снятие symlink rejection и неверную seconds
  conversion.
- `FlySystemBackend.cpp` отдельно компилируется в targeted test target.
- Production target `fic` не собран: в host build environment отсутствует
  `systemd/sd-daemon.h`.
- `git diff --check` — passed.
- Полная сборка проекта НЕ запускалась по явному ограничению задачи.

## Remaining

- При наличии build environment с libsystemd повторить targeted сборку `fic`.
