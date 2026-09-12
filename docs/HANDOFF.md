# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `0c79859`.

## Current task

- Заменить нестабильный глобальный integer offset команды `log_records` на
  opaque per-file cursor без дублирования и потери записей.

## Accepted architecture / invariants

- Cursor версии 1 является base64url-кодированным opaque JSON envelope,
  привязанным к `boot_id`.
- Для каждого файла cursor хранит relative path, `st_dev`, `st_ino` и byte
  offset. Append или изменение порядка другого файла не сдвигает позицию.
- Новый файл читается с начала. Missing/replaced/truncated known file выдаёт
  `reload_required`, после чего GUI выполняет full reload без дедупликации.
- Файлы открываются с `O_NOFOLLOW`, а identity и чтение относятся к одному fd.
- Сохранены limit 1..500, `has_more`, 768 KiB page limit и 16 KiB line limit.

## Completed

- Добавлен testable `LogRecordsReader`; daemon IPC использует `cursor` /
  `next_cursor` вместо `offset` / `next_offset`.
- `LogService` хранит cursor как непрозрачный `QString` и обрабатывает stale
  cursor через bounded full reload.
- Добавлены regression tests для cross-file append, новых и нескольких файлов,
  pagination, inode replacement, truncation и size limits.
- Обновлены IPC и architecture docs.

## Changed areas

- `fic/src/daemon/LogRecordsReader.*`, `fic/src/main.cpp`
- `fic-gui/src/features/logs/services/LogService.*`
- `tests/fic/daemon/LogRecordsReaderTests.cpp`, `tests/CMakeLists.txt`
- `fic/README.md`, `docs/architecture-diagrams.md`

## Validation

- Fresh Ubuntu 24.04 configure: passed с временным GIO pkg-config shim в
  `/tmp`; исходный dependency contract не менялся.
- Полная сборка всех targets: passed.
- Targeted `log_records_reader_tests`, `ipc_protocol_validation_tests` и
  `module_ui_static_checks`: 3/3 passed.
- Полный non-root CTest вне sandbox: 88/88 passed.
- `git diff --check`: passed.

## Remaining

- Коммит не создавать без отдельного запроса пользователя.
- Root-only `command_hash_batch_tests` не запускался: задача не затрагивает
  command-hash lifecycle.
