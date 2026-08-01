# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-01.
- Ветка: `main`.
- Базовый commit: `ce93a1b`.
- Текущая задача: исключить прямую запись группы `fic` в persistent-дерево
  `/opt/fic`, сохранив административный доступ через сокеты.
- Изменения рабочей копии не зафиксированы commit.

## Сделано

- Production IPC-модель не ослаблена: `/run/fic` остается `root:fic 0770`,
  сокеты `fic.sock` и `fic-device.sock` — `0660`.
- Deb/RPM maintainer scripts теперь нормализуют `/opt/fic` как `root:fic`:
  каталоги `2750`, обычные файлы `0640`, файлы в `/opt/fic/bin` — `0750`.
  Группа может читать конфигурацию и БД и запускать клиенты, но не может
  изменять persistent-файлы напрямую.
- Изменены Debian 10/11/12 builders и ALT p11 RPM builder. Актуальные Debian 13
  и Ubuntu 24.04 entry points используют общий Debian 12 builder и наследуют
  новую модель.
- Runtime writers синхронизированы с packaging: command hash store, PID-lock,
  notification spool и SQLite database больше не получают group-write.
- Для root systemd services добавлен `UMask=0027`, чтобы новые SQLite WAL/SHM,
  логи и временные файлы не создавались с более широкими правами.
- Добавлены runtime/static проверки режимов БД, lock/hash файлов, packager'ов и
  service templates.
- Обновлены README, архитектурная документация и инварианты `AGENTS.md`.

## Основные измененные файлы

- `fic-common/fic-core/{include/fic/core/ExclusivePidLock.h,src/CommandHashStore.cpp,src/NotifyUser.cpp}`;
- `fic-common/fic-device-db/src/DB.cpp`;
- `fic/src/scripts/service/*.service.in`;
- `packaging/deb/build-fic-debian{10,11,12}-deb.sh`;
- `packaging/rpm/build-fic-alt-p11-rpm.sh`;
- `tests/paths/RuntimePathsTests.cpp`;
- `tests/trust/CommandHashBatchTests.cpp`;
- `tests/platform/static_checks.py`;
- `README.md`, `AGENTS.md`, `fic/README.md`,
  `packaging/{deb,rpm}/README.md`, `docs/architecture-diagrams.md`.

## Выполненные проверки

- `bash -n` для Debian 10/11/12/13, Ubuntu 24.04 и ALT p11 packager'ов:
  успешно.
- `python3 tests/platform/static_checks.py .`: успешно.
- `python3 tests/paths/static_checks.py .`: успешно.
- `python3 tests/device-control/static_checks.py .`: успешно.
- `cmake -S . -B /tmp/fic-prod-audit.doO0Us -DFIC_TARGET_PLATFORM=alt-p11 -DCMAKE_BUILD_TYPE=Release`:
  успешно.
- `cmake --build /tmp/fic-prod-audit.doO0Us -j2`: успешно, собраны все цели.
- `ctest --test-dir /tmp/fic-prod-audit.doO0Us --output-on-failure`: 21 тест,
  ошибок нет; `admin_socket_tests` и root-зависимый
  `command_hash_batch_tests` штатно пропущены.
- `git diff --check`: успешно.
- Реальные `/opt/fic`, systemd services и Unix-сокеты не изменялись.
- Тяжелые deb/rpm package builds и install/upgrade integration не запускались.

## Что осталось

- На disposable VM проверить upgrade установленного пакета: postinst должен
  убрать group-write у существующих конфигов, БД и бинарников, после чего
  `fic` и `fic-dick` должны продолжить принимать запросы члена группы через
  оба сокета.
- В root-capable CI выполнить `admin_socket_tests` и
  `command_hash_batch_tests`, включая новые проверки `0640`.

## Риски и решения

- `fic` остается высокопривилегированной административной группой daemon API:
  она может менять политики, устройства, hashes и останавливать daemon через
  сокет. Изменение убирает только обход API через прямую запись в `/opt/fic`.
- Direct read SQLite во время работы daemon допускается правами, но
  диагностические инструменты должны открывать БД read-only и не рассчитывать
  на стабильный snapshot без SQLite transaction.
- Compatibility alias и отдельная миграция не добавлялись: maintainer scripts
  сразу нормализуют права текущего дерева при установке или обновлении.
