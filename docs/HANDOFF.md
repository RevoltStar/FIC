# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `9e39784` (rollback base) + незакоммиченный
  follow-up fixup в рабочем дереве.

## Current task

- Follow-up ревизия rollback MVP: исправление ownership semantics SYSCTL,
  strong consistency MutationJournal, fail-closed open/read, enrollment
  whitelist, commit-failure semantics backend'ов + regression tests
  (см. `docs/rollback.md` — авторитетное описание).

## Accepted architecture / invariants

- Rollback строится из фактически выполненных backend-мутаций, а не из
  метаданных политики: нет `Policy::rollback()` и `RollbackStrategy` enum.
- Persistent journal (`fic/src/rollback/`) — единственный источник
  provenance; schema_version 1, atomic write, загрузка fail closed.
  Только реальное отсутствие файла = пустой journal; существующий файл,
  который нельзя открыть/прочитать, и существующий нулевой длины файл —
  ошибки загрузки (fail closed).
- Любая journal-мутация при неудачном persist оставляет in-memory состояние
  логически идентичным дооперационному (включая порядок записей и next_id).
- Lifecycle: `Prepared` записывается до системного изменения, `Applied` —
  после успешного apply/postcondition. Commit `Prepared→Applied` после
  фактического системного изменения при неудаче persist = ошибка apply
  (не маскируется как success); `Prepared` остаётся активным и разрешается
  rollback executor'ом.
- Ownership SYSCTL определяется содержимым FIC managed-артефакта
  (`SysctlConfiguration::inspectManagedValue`), а не текущим effective
  source; внешний источник может перекрывать FIC-запись — запись при
  disable всё равно удаляется. Drift внутри managed-артефакта — `Conflict`.
- Enrollment — явный whitelist (`isSupportedSudoPolicy` /
  `isSupportedFirewallPolicy`); любая неизвестная политика внутри
  DAC/SudoEdit и FIREWALL/HostFiltering — `Unsupported` (без
  default-positive enrollment).
- Rollback выполняется до смены статуса политики; частичный отказ оставляет
  политику ENABLE и повторяем идемпотентно.

## Completed

- `fic/src/rollback/`: `MutationRecord`, `MutationJournal`,
  `DaemonMutationJournal`, `RollbackExecutor`.
- Runtime path `FIC_MUTATION_JOURNAL_FILE` (`/opt/fic/db/mutation-journal.json`).
- Backend hooks: `SysctlConfiguration::removeManagedKey` (ownership по
  managed-файлу; после удаления пересчёт effective value и runtime sysctl),
  `inspectManagedValue`, `SudoersConfiguration::removeManagedGlobalDefault`,
  FIREWALL undo hook, DC undo через device daemon.
- Follow-up fixes: `undoSysctlSetting`/`checkUnrecordedOwnership` (SYSCTL)
  переведены на managed-artifact ownership; `MutationJournal` strong
  consistency + fail-closed open/read + zero-byte invalid; enrollment
  whitelist; commit failure → apply failure в `Sysctl.cpp`, `Sudo.cpp`,
  `FirewallPolicies.cpp`, DC enable path `fic/src/main.cpp`.
- `tests/CMakeLists.txt`: `mutation_journal_tests` теперь линкует
  `fic-policy` (include `fic/policy/PolicyDependency.h`).
- `docs/rollback.md` обновлён по всем пунктам follow-up.

## Changed areas

- `fic/src/rollback/`, `fic/src/modules/sysctl/`,
  `fic/src/modules/dac/sudo/`, `fic/src/modules/firewall/`,
  `fic/src/main.cpp`, `tests/fic/rollback/`, `tests/CMakeLists.txt`,
  `docs/rollback.md`

## Validation

- `mutation_journal_tests`: 19/19 passed (exit 0).
- `rollback_executor_tests`: 23/23 passed (exit 0).
- `g++ -fsyntax-only` для `Sysctl.cpp`, `Sudo.cpp`, `FirewallPolicies.cpp`,
  `main.cpp` — passed.
- `git diff --check` — passed.
- Полный CMake configure + build (`build-check`, ubuntu-24.04): запуск
  выполнялся; результат зафиксировать при завершении (см. Remaining).

## Remaining

- Изменения не закоммичены.
- Если full CTest не был завершён — прогнать
  `ctest --test-dir build-check --output-on-failure`.
- Известное same-class ограничение вне follow-up scope: SUDO
  `removeManagedGlobalDefault`/legacy-check по-прежнему используют
  effective-source семантику (как для SYSCTL не переводились на
  managed-artifact ownership); при перекрытии managed sudoers-значения
  главным sudoers disabling может дать NothingToDo вместо удаления FIC
  записи. Потенциальный следующий fix, требует отдельной задачи.
