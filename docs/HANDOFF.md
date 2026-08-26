# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit hardening-задачи: `1792350c0f709562141cea765c682580fcec2c89`.

## Current task

- Hardening нативной ALT p11 `control`-интеграции `fic-pam-faillock` после
  воспроизведения пяти fail-closed/TOCTOU дефектов исходной реализации.

## Accepted architecture / invariants

- Значения FIC policies и наличие package-level PAM-топологии управляются
  раздельно: facility `fic-pam-faillock` не передаёт policy options в PAM.
- Facility является тонким adapter к root-only offline maintenance API daemon:
  `fic --maintenance pam-alt-faillock status|enable|disable`.
- Менеджер изменяет только `/etc/pam.d/system-auth-local-only`, использует
  размеченные FIC-блоки, atomic write, межпроцессный lock, строгую проверку
  структуры и postcondition с rollback.
- Чужие `pam_faillock`-строки не присваиваются и не удаляются. Неполные,
  дублированные, изменённые или неоднозначные managed-блоки обрабатываются
  fail-closed.
- Для достижимого успешного пути между `preauth` и `[default=die] authfail`
  исходный `auth required pam_tcb.so ...` временно представлен как
  `auth sufficient pam_tcb.so ...`; его точные исходные байты хранятся в
  managed metadata и восстанавливаются byte-for-byte при disable.
- `pam_tcb.so` обязан быть последним исполняемым auth-правилом локального
  stack; effective graph проверяется до первой записи, а semantic postcondition
  в SSS mode относится к управляемой local-only ветви.
- Atomic replacement может быть привязан к ожидаемым `st_dev`/`st_ino`; это
  обнаруживает замену target inode до commit, но не является kernel-level CAS.
- IPC API остаётся version `1`; Debian/Ubuntu packaging этой задачей не менялся.

## Completed

- Добавлен ALT p11 profile path и `AltPamFaillockTopologyManager` с операциями
  status/enable/disable, безопасной работой с файлом и rollback.
- Общий PAM parser открыт через `PamConfiguration::parseRulesContent` и
  переиспользуется менеджером без параллельного parser implementation.
- Добавлены maintenance CLI dispatch и native control facility с полным
  `help/list/summary/status/enabled/disabled` contract.
- RPM lifecycle поддерживает disabled-by-default clean install, сохранение
  control state при upgrade и безопасное удаление topology при final erase.
- Добавлены unit/static/packaging tests, включая `pam_passwdqc` detection,
  malformed/external topology, idempotency, rollback и exact restoration.
- Обновлена релевантная RPM, daemon и architecture документация.
- Исправлены подтверждённые findings A-E: небезопасный auth tail, ложный отказ
  SSS mode, позднее обнаружение внешнего `pam_faillock`, угадывание позиции при
  disable и перезапись заменённого inode.
- Добавлены regression tests для каждого finding и прямой тест expected target
  identity в `AtomicFileWriter`.

## Changed areas

- `fic/src/modules/identity_access/pam/`, `fic/src/main.cpp`;
- `fic-common/fic-core` atomic file writer;
- relevant PAM и filesystem tests;
- `packaging/rpm/` documentation;
- `fic/README.md`, `docs/architecture-diagrams.md`.

## Validation

- ALT p11 configure и полный build в `/tmp/fic-alt-pam-hardening-build` —
  успешно.
- Targeted 7/7: topology/configuration, atomic writer, platform profile и
  packaging/static tests — успешно.
- Полный CTest: 41 passed, 4 skipped, 2 unrelated failures из 47. Существующий
  `ipc_protocol_validation_tests` падает на API v1 assertion; `path_layout_static_checks`
  видит два пустых obsolete directory в рабочем checkout. Затронутые tests
  прошли.
- `bash -n` для RPM scripts — успешно.
- Пересборка RPM была запущена, но Docker daemon заблокировался на I/O и не
  ответил даже на `docker ps`; новый package/runtime прогон не завершён.
- `git diff --check` — успешно.

## Remaining

- `PamPasswdqc` распознаётся parser как effective provider, но существующие
  option policies и `required_pam_enforcement` принимают password-quality
  provider только `pam_pwquality`. Поддержка ALT `pam_passwdqc` как источника
  policy options является отдельной задачей.
- `pam_pwhistory` не добавлялся: canonical ALT p11 stack его не содержит, а
  текущая задача не определяет безопасную topology/option migration для него.
- Существующий unrelated `ipc_protocol_validation_tests` failure не исправлялся.
- До release gate нужно повторить RPM build и реальные ALT p11 local/SSS,
  external-topology и final-erase сценарии после восстановления Docker daemon.
- Между последним `lstat` и `rename` остаётся узкое userspace TOCTOU-окно;
  `st_dev`/`st_ino` contract предотвращает воспроизведённую замену до writer,
  но не заявляется как абсолютный filesystem CAS.
