# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `f5bcf592519d508ebc069aa5cebd1309d0e16b7e`.

## Current task

- Нативная ALT p11 `control`-интеграция для package-level управления
  топологией `pam_faillock` в `system-auth-local-only`.

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

## Changed areas

- `fic/src/modules/identity_access/pam/`, `fic/src/main.cpp`;
- `fic/src/platform/` ALT p11 profile;
- `packaging/rpm/`;
- relevant PAM, platform и packaging tests;
- `fic/README.md`, `docs/architecture-diagrams.md`.

## Validation

- ALT p11 configure и полный build в `/tmp/fic-alt-pam-build` — успешно.
- Targeted PAM topology/configuration, platform profile и packaging/static
  tests — успешно.
- Полный CTest: 42 passed, 4 skipped, 1 unrelated failure — существующий
  `ipc_protocol_validation_tests` assertion об API v1 request; затронутые этой
  задачей tests прошли.
- `bash -n` для RPM scripts — успешно.
- `./packaging/rpm/build-fic-alt-p11-rpm-docker.sh 0.0.0-alpha` — успешно;
  итоговые RPM dependency metadata содержат `control`, `pam >= 1.7.1` и
  `pam-config >= 1.10.0`.
- В изолированном ALT p11 container с `pam-config-1.10.0-alt0.p11.2`,
  `pam-1.7.1-alt1`, `control-0.8.0-alt3` проверены clean install, enable,
  повторный enable, enabled/disabled upgrade и final erase: состояние
  сохраняется, managed-блоки не дублируются, исходный PAM-файл
  восстанавливается byte-for-byte. RPM устанавливались с `--nodeps`, поскольку
  builder image не содержит unrelated runtime dependencies; metadata проверена
  отдельно.
- `git diff --check` — успешно.

## Remaining

- `PamPasswdqc` распознаётся parser как effective provider, но существующие
  option policies и `required_pam_enforcement` принимают password-quality
  provider только `pam_pwquality`. Поддержка ALT `pam_passwdqc` как источника
  policy options является отдельной задачей.
- `pam_pwhistory` не добавлялся: canonical ALT p11 stack его не содержит, а
  текущая задача не определяет безопасную topology/option migration для него.
- Существующий unrelated `ipc_protocol_validation_tests` failure не исправлялся.
