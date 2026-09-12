# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `0832104`.

## Current task

- Устранить рост wire cursor, удержание всех log FD и продвижение offset за
  незавершённую строку в `log_records` после `c47f4c3`.

## Accepted architecture / invariants

- GUI продолжает передавать cursor как непрозрачную строку.
- Wire cursor v2 — фиксированный 34-byte token; daemon хранит ограниченно до 64
  LRU snapshots с `version`, `boot_id` и per-file path/dev/inode/offset.
- Неизвестный корректный token, смена inode, исчезновение файла и truncation
  требуют безопасного full reload через `reload_required`.
- Одновременно открыт максимум один log-файл; `open`/`fstat` errors являются
  service errors, а не причиной пропуска файла.
- Byte offset продвигается только после полностью завершённой `\n` записи.

## Completed

- `LogRecordsReader` стал stateful daemon-owned service с bounded cursor store.
- Чтение разделено на последовательный metadata snapshot и последовательное
  чтение с повторной identity validation.
- Добавлены regression cases для 1100 файлов при `RLIMIT_NOFILE=32`, IPC cursor
  size, partial-line completion и явной ошибки открытия.
- Сохранены проверки cross-file append, pagination, inode replacement,
  truncation и line/page limits; обновлена IPC/architecture documentation.

## Changed areas

- `fic/src/daemon/LogRecordsReader.*`, `fic/src/main.cpp`
- `tests/fic/daemon/LogRecordsReaderTests.cpp`
- `fic/README.md`, `docs/architecture-diagrams.md`

## Validation

- Полная сборка `/tmp/fic-log-cursor-build`: passed.
- Targeted `log_records_reader_tests`, `ipc_protocol_validation_tests`,
  `module_ui_static_checks`: 3/3 passed.
- Полный CTest вне sandbox от UID 1000: 88/88 выполненных passed;
  root-only `command_hash_batch_tests` штатно skipped.
- `git diff --check`: passed.

## Remaining

- Коммит не создавать без отдельного запроса пользователя.
