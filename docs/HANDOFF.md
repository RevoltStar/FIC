# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `5472f9d`.

## Current task

- Исправление review-замечаний к discovery и session identity contract
  `disable_kde_lock_screen_media_controls`.

## Accepted architecture / invariants

- Policy применяет `showMediaControls=false` ко всем текущим KDE-сессиям:
  foreground/background, local/remote и безопасно идентифицированным startx.
- Достоверно классифицированные non-KDE сессии находятся вне scope; context
  query failure и пустой/UNKNOWN desktop identity дают общий failure.
- Нет текущих KDE-сессий — успешный результат/not applicable; ошибка хотя бы
  в одной KDE-сессии — общий failure.
- KDE backend сохраняет запись и readback `kscreenlockerrc`, затем вызывает
  существующий DBus reload.
- `screenlock_timeout` сохраняет прежний local native-graphical selector.

## Completed

- Добавлен отдельный KDE-policy selector без `Active`; closing/dead исключены,
  native graphical выбираются всегда, TTY — при наличии точного agent socket.
- Session agent принимает remote sessions и прямой TTY/startx context только
  при согласованных XDG session type, desktop и display; UID-only fallback не
  выбирает TTY.
- Daemon допускает `logind Type=tty` → agent `x11/wayland/mir` только с
  соответствующим display и сохраняет socket owner/peer/session-id checks.
- Документирован first-public-release contract: старый development `OSS.conf`
  пересоздаётся, migration и schema bump не добавляются.

## Changed areas

- KDE policy applicability и localization;
- `fic/src/session/SessionLocator*`, `SessionSelection*`, agent client/executor;
- `fic-session-agent` identity resolver;
- session-agent/upgrade documentation;
- relevant CMake regression tests и static checks.

## Validation

- Targeted build daemon, session agent и четырёх test targets — успешно.
- Targeted CTest/static checks — успешно; socket client test отдельно успешно
  вне sandbox.
- Полная ALT p11 build — успешно.
- Полный CTest из 53 tests: 48 passed, 4 environment-skipped, 1 existing unrelated
  failure `ipc_protocol_validation_tests` (устаревшее ожидание reject API v1).
- Все static checks прошли.
- `git diff --check` — успешно.

## Remaining

- Изменения текущей задачи не закоммичены.
- Existing unrelated `ipc_protocol_validation_tests` failure не исправлялся.
