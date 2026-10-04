# FIC handoff

## Current base

* branch: `main`
* base commit: `240410f` + follow-up «Harden SUDO scoped-defaults provenance and
  recovery lifecycle»

## Current task

Доработка подсистемы SUDO после `240410f`: provenance-safe обёртки
scoped `Defaults`, crash-consistent транзакция, reconciliation-safe refresh и
E2E-тест journal → filesystem. Выполнено.

## Accepted architecture / invariants

* `SudoersConfiguration` остаётся владельцем парсинга sudoers, include-графа и
  конфигурационных примитивов. Вся remediation scoped `Defaults` вынесена в
  `SudoersScopedDefaultsTransaction` (targets/dedup, глобальный инвентарь,
  provenance, refresh-планирование, state-bound транзакция, компенсация,
  typed outcome, rollback). Наружу у конфигурации остались только
  `graphDocuments()/graphEntries()` и `validateConfiguration()`.
* Payload `UndoReleaseSudoScopedDefaults` = `{policyName, previousProofs,
  targetProofs}`, где proof = `{wrapperId, payloadDigest}`. Digest — SHA-256 от
  **точных подавленных байтов вместе с terminator-ами строк**
  (`fic::core::ContentDigest`, `SudoPhysicalLine`). Инвариант:
  `previousProofs ⊆ targetProofs`.
* Rollback пересчитывает digest **до** снятия обёртки; расхождение — `Conflict`
  с нулём записей.
* Только `NoMutation` / `MutatedAndCompensated` разрешают удалить `Prepared`.
* Все мутационные пути SUDO сериализуются одним `SudoersConfiguration::mutationMutex()`.
* Include-лексика: кавычки — **verbatim** (как в upstream `expand_include`),
  некавыченный backslash — fail closed.

## Accepted architecture / invariants

* Include-подграмма разбирается специализированным лексером
  `SudoersIncludeDirective`: директива распознаётся ДО обработки комментариев
  (`#` — одновременно начало комментария и часть legacy `#include`).
  Поддержаны `"..."`, экранирование пробелов и обратного слэша, trailing
  inline-комментарий, относительный pathname, continuation. Неподдерживаемое и
  неоднозначное — явный fail-closed, НЕ silent ignore (тихий пропуск сузил бы
  активно подключённый граф). `%`-подстановки остаются fail-closed.
* Две НЕСМЕШИВАЕМЫЕ модели владения SUDO: managed scalar Defaults
  (`zzzz-fic`, значение ключа) и source-edit wrapper (`sudo_disable_scoped_defaults`).
* `sudo_disable_scoped_defaults`: запрещены все четыре scope (`:`, `@`, `>`, `!`).
  Детекция строго синтаксическая — алиасы/`%group`/netgroups/отрицание НЕ
  вычисляются, само наличие scoped-записи является нарушением.
* Обёртки `#@FIC_SUDO_DISABLED_*` — собственный namespace SUDO (SSH-маркеры не
  переиспользуются). Исходные байты живут внутри обёртки; journal payload —
  только policy identity + wrapper ids (доказательство разрешения, не бэкап).
  Snapshot всего `/etc/sudoers` не используется.
* Crash-consistency apply-транзакции НЕ заявляется: восстановление — это
  `Prepared`-запись журнала, подготовленная ДО файловой мутации; wrapper ids
  генерируются до journaling, поэтому payload сразу полный.
* `exempt_group` имеет ровно одного владельца — `sudo_exempt_group_disable`.
  `sudo_require_authentication` больше не переписывает `exempt_group`.
* Обратная защита: обязательная зависимость включённой политики не отключается
  раньше неё (`enabledRequiredDependents` в `PolicyDependencyGraph`). Без
  скрытого cascade-disable.

## Completed

* Новые компоненты: `SudoersIncludeDirective`, `SudoersScopedDefaults`,
  `SudoersDisabledWrapper` + новые политики `sudo_disable_scoped_defaults`,
  `sudo_exempt_group_disable`.
* `MutationRecord`/`MutationJournal`/`RollbackExecutor`: payload
  `UndoReleaseSudoScopedDefaults`, whitelist enrollment без default-positive,
  orphan-обёртка без активной записи журнала → fail closed.
* Зависимости и обратный guard; регрессии в
  `SudoersConfigurationTests`, `PolicyExecutionPlannerTests`,
  `RollbackExecutorTests`.

Follow-up поверх `240410f`:

* `fic::core::ContentDigest` (SHA-256 через OpenSSL EVP) + `SudoPhysicalLine`
  (line + оригинальный terminator) — byte-exact apply/rollback, включая CRLF.
* `SudoersScopedDefaultsTransaction`: physical dedup, глобальный инвентарь
  обёрток, проверка provenance по id+digest, `planRefresh`, `classifyPrepared`,
  typed `SudoScopedDefaultsOutcome`, state-bound apply/release/компенсация
  через `captureTargetState()`/`expectedTargetState`.
* Payload журнала `{policyName, previousProofs, targetProofs}` + валидаторы
  чтения/записи (канонические id, канонические digest, уникальность,
  `previous ⊆ target`, refresh-guards для `Prepared`/`RollbackFailed`/`Applied`).
* Единый `SudoersConfiguration::mutationMutex()` для всех пяти мутационных
  путей SUDO (включая обе rollback-ветки).
* Include-лексика: кавычки verbatim; некавыченный backslash — fail closed.
* Новый E2E-таргет `sudo_scoped_defaults_lifecycle_tests` (8 сценариев) и
  `content_digest_tests`.

## Changed areas

* `fic/src/modules/dac/sudo/*` (backend, транзакция, политики)
* `fic/src/rollback/{MutationRecord.h,MutationJournal.cpp,RollbackExecutor.cpp}`
* `fic-common/fic-core/{include/fic/core/integrity,src/integrity}`
* `tests/CMakeLists.txt`,
  `tests/fic/rollback/SudoScopedDefaultsLifecycleTests.cpp`,
  `tests/fic/modules/dac/SudoersConfigurationTests.cpp`
* `docs/{rollback.md,architecture-diagrams.md,HANDOFF.md}`

## Validation

* `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=ubuntu-24.04`
* `cmake --build build-check -j4` — RC=0
* `ctest --test-dir build-check --output-on-failure` — 119/119 PASS
  (`command_hash_batch_tests` — Skipped, не связан с задачей)
* `sudo_scoped_defaults_lifecycle_tests` — RC=0 (8 E2E-сценариев)
* `content_digest_tests` — RC=0
* `visudo-rs 0.2.13` использован как oracle для синтаксиса обёрток.
  Для некавыченного backslash oracle непригоден: `visudo-rs` отказывает по
  ownership каталога **до** разбора include, поэтому эта форма закрыта
  fail-closed по upstream-исходникам (`toke.l` `<INSTR>` + `expand_include`),
  а не проверкой на хосте.

## Remaining

* Полный E2E с реальным применением политик на хосте не запускался (unsafe
  runtime validation по AGENTS.md).
* `+=`/`-=` для существующих четырёх scalar-политик сознательно не реализованы:
  подтверждённого false-positive под задачу нет.
* `%h`-подстановка в include остаётся fail-closed намеренно.
