# FIC: передача контекста

## Current base

- Ветка `main`.
- База до corrective commit:
  `92eaf02aa24b0a2883ef1f972416f0773d39f5a6`.

## Current task

- Устранить false `MandatoryGlobal` для KDE `screenlock_timeout`, исправить
  current-session reload ordering и standard Ubuntu/Kubuntu XDG metadata.

## Accepted architecture / invariants

- `GNOME` остаётся `MandatoryGlobal`; `KDE`, `XFCE` и `FLY` — `SessionOnly`;
  `LXQt` — `Unsupported`.
- Plasma 5/6 позволяет пользователю изменить KConfig graph реального
  KScreenLocker через session environment; штатный cross-generation
  root-authoritative механизм не найден.
- KDE session reconciliation всегда выполняет
  `org.kde.screensaver.configure` перед final file readback, даже если initial
  read уже совпал. Readback не доказывает runtime-cached timeout.
- `KdeSystemBackend`, dual-file protection и optional `fic-kconfig-verifier`
  сохранены как groundwork, но production `screenlock_timeout` не публикует
  KDE global requirements.

## Completed

- Проверен upstream lifecycle: Plasma 5 X11 — `ksmserver`, Plasma 5 Wayland —
  `kwin_wayland`, Plasma 6 — `kwin`; все зависят от user-controlled session
  environment.
- KDE переведён в `SessionOnly`; KDE-only scope публикует 0 global
  contributions, mixed GNOME+KDE — только четыре GNOME contributions.
- Исправлен KDE ordering: read, optional five writes, configure, final read.
- В Ubuntu 24.04/26.04 metadata добавлен реальный Kubuntu defaults directory;
  Debian 12/13 и ALT p11 перепроверены без изменений.
- Три требуемых negative control дали ожидаемые test failures, затем исходники
  восстановлены.

## Changed areas

- `OSS_screenlock_timeout` и `KdeScreenLockTimeoutHandler`.
- Screen-lock/session/static contract tests.
- Ubuntu platform profiles и profile tests.
- KDE/session architecture documentation.

## Validation

- Targeted build шести affected unit targets — passed.
- Targeted CTest: 8/8 passed, включая оба relevant static checks.
- Platform static contract проверил точные hierarchy всех пяти profiles.
- Negative controls: KDE `MandatoryGlobal`, KDE global contributions и skipped
  already-correct reload — каждый был пойман соответствующим regression.
- `git diff --check` — passed.
- Отдельные Ubuntu 26.04/Debian 12/13 build directories не регенерируются на
  хосте без `libsystemd`; ALT p11 `platform_profile_tests` собрался, но упал на
  существующем unrelated provider-metadata кейсе.
- `clang-format` на хосте отсутствует.
- Live Plasma session отсутствовала; runtime D-Bus experiment не выполнялся.
- Полная сборка проекта НЕ запускалась по явному ограничению задачи.

## Remaining

- Повторить live D-Bus convergence smoke при наличии тестовой Plasma 5/6
  сессии; это не меняет fail-safe `SessionOnly` decision.
