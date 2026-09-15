# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `614af8666cbdfced575979a8800b5d1c2c59d21d`.
- Рабочее дерево содержит незакоммиченную notification/packaging правку.

## Current task

- Перевести desktop notification dispatcher с `runuser` на `setpriv` и
  закрепить реальные DEB/RPM runtime dependencies.

## Accepted architecture / invariants

- Dispatcher запускает `notify-send` через `setpriv` с numeric UID/primary GID,
  initialized supplementary groups, очищенными inheritable capabilities и
  reset environment.
- В дочернее окружение явно передаются только session D-Bus coordinates;
  `DISPLAY` для notification delivery не используется.
- ALT RPM зависит от `notify-send` и `util-linux`; Debian-family DEB — от
  `libnotify-bin` и `util-linux`.
- Существующий recipient filter сохраняется: уведомления получают только
  пользователи активных локальных graphical sessions, состоящие в группе
  `fic`. Обычные пользователи вне группы `fic` уведомления не получают.

## Completed

- `runuser` удалён из runtime dispatcher без fallback.
- Добавлены проверки обязательных runtime commands и прямой вызов
  `env notify-send` с отдельными аргументами без shell evaluation.
- Обновлены DEB/RPM dependency declarations и packaging README.
- Добавлен `notification_packaging_static_checks` для dispatcher, service и
  package metadata contracts.

## Changed areas

- `fic/src/resources/notify/fic-notify-dispatcher`
- `packaging/deb/`, `packaging/rpm/`
- `tests/CMakeLists.txt`
- `tests/integration/packaging/notification-packaging-checks.py.in`

## Validation

- CMake configure `build-alt-sss` для `alt-p11` — passed.
- Targeted CTest: 6/6 passed (`notification_packaging_static_checks`,
  path/platform/PAM packaging static checks, version/release contracts).
- Direct notification packaging check — passed.
- `bash -n` для dispatcher и обоих package builders — passed.
- Repository search: runtime `runuser` отсутствует; слово осталось только в
  regression assertion.
- `git diff --check` — passed.

## Remaining

- Изменения не закоммичены.
- DEB/RPM artifacts и полный проект не собирались; полный CTest не запускался.
- Runtime delivery в реальной graphical session не проверялась.
- Непривилегированный local smoke полного `setpriv --init-groups` ожидаемо
  завершился `Operation not permitted`; dispatcher штатно запускается от root.
