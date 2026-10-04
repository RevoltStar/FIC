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

Follow-up поверх `c325e92`:

* **Wrapper format**: явная provenance terminator'а —
  `#@FIC_SUDO_DISABLED_LINE@eol=<lf|crlf|none>@<content>`. Framing обёртки всегда
  LF-терминирован, поэтому подавленная строка без финального newline больше не
  сливается с END-маркером. Digest считается от ORIGINAL-байтов; правка `eol`
  даёт mismatch, а не silent normalization.
* **Модель результата** разделена на причину (`SudoScopedDefaultsResultKind`)
  и состояние ФС (`SudoScopedDefaultsFilesystemState`). Судьбу `Prepared`
  решает ТОЛЬКО состояние ФС: `Unchanged`/`Compensated` разрешают discard.
* **Partial-write fix**: `settleFilesystemState()`/`settleWithCompensation()`
  выводят состояние из ВСЕЙ транзакции — падение на последнем файле больше не
  сообщает «ничего не записано», пока в первом лежит обёртка.
* **Graph-snapshot CAS**: `captured.content == GraphDocument.content` перед
  построением `newContent`; mismatch → Conflict, ноль записей, нужен reload+re-plan.
* **Proof↔target binding**: `PlannedScopedDefaultsMutation{target, proof}`;
  сортировка перемещает пары целиком, `proofCursor` удалён; digest
  перепроверяется по захваченному снимку перед генерацией обёртки.
* **Prepared recovery в production**: `ScopedDefaultsLifecycle` — journal state
  machine (recovery, ownership validation, planning, prepare→apply→commit/discard).
  `CompleteTarget` → commit существующей записи; `CompletePrevious` → discard;
  `Indeterminate` → `compensateToPrevious()` либо fail closed. Новые id поверх
  unresolved Prepared не минтятся.
* **Ownership preflight** выполняется перед ЛЮБОЙ мутацией, не только в no-op:
  orphan/drift блокирует reconciliation.
* **Одна активная запись**: `collectActiveOwnership()` fail closed при >1.
* **Rollback compensation** + сохранение provenance при частичном rollback.
* **Refresh provenance (P0)**: неудачный REFRESH больше не может удалить
  provenance уже существующих обёрток. `Prepared(previous=P,target=P+F)` при
  доказанно-durable previous нормализуется в `Applied(target=P)` на том же id
  (`MutationJournal::normalizeSudoScopedDefaultsPreparedToPrevious()`), а
  `discard()` остаётся только для fresh-переходов с пустым `previous`.
* **Durability barriers**: commit / discard / normalize / rollback Success
  требуют `ensureTargetDurableIfCurrentState()` по `canonicalPath` каждой proof'ы.
  Видимое состояние ≠ durable.
* **Proof identity**: `wrapperId + canonicalPath + payloadDigest`;
  `previous ⊆ target` сравнивается по полной идентичности.
* **Финальное доказательство владения** по `targetProofs` выполняется после
  мутации и reload, непосредственно перед commit.
* **Release**: глобальный инвентарь строится по тем же captured-снимкам,
  против которых выполняются CAS-записи.
* **Селективная компенсация** `restoreSelectedSudoDisabledEntries()` позволяет
  откатить частичный target, не снимая previous-обёртки.
* **Snapshot-bound proof (939e6e2+)**: `captureProofAndGraphState()` →
  `proveCapturedState()` → `proveCapturedStateDurable()` работают на ОДНИХ
  `AtomicTargetState`; между proof и durability нет перечитывания ФС.
* **Exact vs ReleaseSubset**: `ScopedDefaultsProofMode`. Exact требует
  физического наличия КАЖДОГО proof'а (минус = провал); releasedIds допустимы
  только в ReleaseSubset (rollback). Глобальная полнота решается по всему
  captured inventory.
* **Семантика на тех же captures**: активный scoped Defaults — start-строка вне
  FIC-обёртки; проверяется на тех же снимках, что и ownership.
* **Typed absence**: `ensureTargetAbsentDurableIfCurrentState()`; ошибка
  capture (symlink/каталог/прав/I-O) больше не считается отсутствием.
* **Rollback capture set**: весь include-graph ∪ все proof canonicalPath.
* **Test registry (§37/§38)**: AA–AH были определены, но НЕ вызывались
  (фактически выполнялось 27 из 35). Введён registry + runtime-счётчик, который
  печатает `Executed N of N lifecycle test functions`. Это устранило ложное
  сообщение «35 сценариев» в предыдущем отчёте.
* **classifyCaptured() (§1–§3)**: Prepared-классификация работает по capture
  `graph ∪ previous ∪ target` и по полной identity (id+path+digest).
* **Fresh CompletePrevious durability (§4/§5)**: discard только после durable
  доказательства отсутствия target-владения.
* Новые регрессии AJ (target-обёртка скрыта изменением include topology) и
  AK (fresh crash-before-write по-прежнему восстанавливается).
* **Include lexer**: escape-семантика upstream `copy_string()` для кавыченных и
  некавыченных путей (`\xHH`→hex, `\c`→c). Подтверждено по исходникам sudo
  1.9.13 (debian-12) и текущим — поведение идентично.

## Changed areas

* `fic/src/modules/dac/sudo/{SudoersDisabledWrapper,SudoersScopedDefaultsTransaction,SudoersScopedDefaultsLifecycle,SudoersIncludeDirective}.*`
* `fic/src/modules/dac/sudo/policies/DAC_sudo_disable_scoped_defaults.cpp`
* `fic/src/rollback/RollbackExecutor.cpp`
* `tests/fic/rollback/SudoScopedDefaultsLifecycleTests.cpp`,
  `tests/fic/modules/dac/SudoersConfigurationTests.cpp`, `tests/CMakeLists.txt`,
  `fic/src/rollback/MutationJournal.{h,cpp}`
* `docs/{rollback.md,HANDOFF.md}`

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
