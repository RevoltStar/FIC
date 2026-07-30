# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-07-30.
- Ветка: `main`.
- Базовый commit: `4c240a0`.
- Текущая задача: ограничить package trust sync только executable-кандидатами
  из скомпилированного `profile.executables.entries`.
- Реализация и локальная проверка завершены, изменения не зафиксированы commit.

## Сделано

- Добавлен `fic --trust-sync-platform-affected`: он читает измененные пути,
  выбирает только совпавшие profile candidates и группирует их по
  `ExecutableId`.
- Посторонний список путей завершается успешно до инициализации production
  runtime paths, обращения к пакетной базе и записи `commandhash.txt`.
- Полная команда `fic --trust-sync-platform` сохранена для первичной установки.
- Добавлен `fic --trust-list-platform-paths`; Debian/Ubuntu packaging генерирует
  из него точные `dpkg interest-noawait` triggers вместо четырех каталогов.
- Debian postinst передает имена активированных triggers в affected-режим.
- ALT file-trigger передает FIC полный список измененных RPM-путей через stdin,
  не потребляя первую строку в shell.
- Для затронутых логических executable атомарно удаляются hashes всех прежних
  candidates и записывается hash фактически выбранного resolver пути. Это
  корректно обрабатывает удаление и переключение `/bin`/`/usr/bin` aliases.
- Добавлены unit/static tests и обновлена документация trust-sync потока.

## Измененные файлы

- `fic/src/main.cpp`
- `fic/src/trust/PackageTrustSync.{h,cpp}`
- `fic/src/trust/PackageTrustSelection.{h,cpp}`
- `fic-common/fic-core/include/fic/core/CommandHashStore.h`
- `fic-common/fic-core/src/CommandHashStore.cpp`
- `fic-common/fic-core/include/fic/core/ConfigFileHandler.h`
- `fic-common/fic-core/src/ConfigFileHandler.cpp`
- `packaging/deb/build-fic-debian12-deb.sh`
- `packaging/rpm/fic-trust-sync.filetrigger`
- `tests/CMakeLists.txt`
- `tests/platform/static_checks.py`
- `tests/trust/CommandHashBatchTests.cpp`
- `tests/trust/PackageTrustSelectionTests.cpp`
- `tests/file-handler/FileHandlerOptionsTests.cpp`
- `README.md`
- `fic/README.md`
- `packaging/deb/README.md`
- `packaging/rpm/README.md`
- `docs/architecture-diagrams.md`
- `docs/HANDOFF.md`

## Выполненные проверки

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=alt-p11`: успешно.
- `cmake --build build-check -j2`: успешно, собраны все цели.
- `ctest --test-dir build-check --output-on-failure`: 15 тестов, ошибок нет;
  `admin_socket_tests` и root-зависимый `command_hash_batch_tests` штатно
  пропущены.
- `python3 tests/platform/static_checks.py .`: успешно.
- `bash -n` для общих Debian 12/13/Ubuntu packaging entry points, ALT builder и
  ALT file-trigger: успешно.
- `build-check/fic/fic --trust-list-platform-paths`: успешно, выведены
  candidates профиля `alt-p11`.
- `git diff --check`: успешно.

## Что осталось

- Реальная установка постороннего и контролируемого пакета в ALT/Debian VM не
  запускалась: это изменяет состояние хоста и требует пакетного тестового
  окружения.
- Deb/RPM-пакеты не собирались.
- Root-зависимый `command_hash_batch_tests`, включая новый batch remove/update,
  в текущем непривилегированном окружении не выполнился. Низкоуровневое
  `ConfigFileHandler::removeValue` отдельно покрыто успешно выполненным
  `file_handler_options_tests`.

## Риски и решения

- ALT по-прежнему запускает небольшой file-trigger process после RPM-
  транзакций, но посторонние пути теперь отбрасываются до production runtime
  initialization, package query и hash-store write.
- Exact Debian triggers генерируются запускаемым бинарником с тем же
  compile-time профилем, поэтому список paths не дублируется в packaging.
- Affected-режим доступен только root и предназначен для package hooks; это не
  daemon IPC API.
- При совпадении любого candidate синхронизируется соответствующий логический
  `ExecutableId`, а не только строка пути: resolver может выбрать другой
  существующий alias после завершения пакетной транзакции.
