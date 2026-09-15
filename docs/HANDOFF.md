# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `52f975b` («Переходим с runuser на setpriv»).
- Рабочее дерево содержит незакоммиченную rollback-правку.

## Current task

- MVP системы rollback: при `policy disable` отменять изменения ОС, ранее
  выполненные FIC, для SYSCTL / SUDO / FIREWALL / DC на основе persistent
  mutation journal (см. `docs/rollback.md` — авторитетное описание).

## Accepted architecture / invariants

- Rollback строится из фактически выполненных backend-мутаций, а не из
  метаданных политики: нет `Policy::rollback()` и `RollbackStrategy` enum.
- Persistent journal (`fic/src/rollback/`) — единственный источник
  provenance; schema_version 1, atomic write, загрузка fail closed.
- Lifecycle: `Prepared` записывается до системного изменения, `Applied` —
  после успешного apply/postcondition.
- Rollback выполняется до смены статуса политики; частичный отказ оставляет
  политику ENABLE и повторяем идемпотентно.
- Владение: значение, уже соответствовавшее политике до apply, мутацией не
  записывается и при disable не трогается; drift FIC-owned значения —
  `Conflict` (fail closed).
- Enrollment: Supported — SYSCTL, DAC/SudoEdit managed Defaults,
  FIREWALL/HostFiltering, DC/DeviceControl category features.
  Unsupported — `sudo_require_authentication`, `exclusive_firewall_control`,
  DC non-category. Остальное — NotEnrolled (legacy disable).

## Completed

- `fic/src/rollback/`: `MutationRecord`, `MutationJournal`,
  `DaemonMutationJournal`, `RollbackExecutor`.
- Runtime path `FIC_MUTATION_JOURNAL_FILE` (`/opt/fic/db/mutation-journal.json`)
  через `FicInstallLayout.cmake` / `FicPathDefaults.h.in` /
  `FicRuntimePaths`.
- Backend hooks: `SysctlConfiguration::removeManagedKey` (с пересчётом
  effective value и runtime sysctl), `SudoersConfiguration::
  removeManagedGlobalDefault` (drift check, visudo validation, удаление
  пустого managed-файла с FIC header), `Sysctl::managedResource`,
  `Sudo::managedResource`, FIREWALL undo hook в `FirewallBackend`,
  DC undo через device daemon IPC в daemon wiring.
- `Policy::policyRef()` (fic-policy) для стабильной ссылки на политику.
- Daemon: `disable()` выполняет rollback перед сменой статуса
  (`main_function.cpp`); DC enable записывает Prepared-мутации
  перед `device_regenerate_policy` и коммитит после успеха.
- `docs/rollback.md` — описание контракта.
- Тесты: `tests/fic/rollback/MutationJournalTests.cpp` (13),
  `tests/fic/rollback/RollbackExecutorTests.cpp` (20), зарегистрированы
  в `tests/CMakeLists.txt` как `mutation_journal_tests`,
  `rollback_executor_tests`.

## Changed areas

- `fic/src/rollback/` (новое), `tests/fic/rollback/` (новое)
- `fic/src/daemon/main_function.{h,cpp}`, `fic/src/main.cpp`
- `fic/src/modules/sysctl/`, `fic/src/modules/dac/sudo/`,
  `fic/src/modules/firewall/`, `fic/src/modules/dc/DC.cpp`
- `fic-common/fic-policy/include/fic/policy/Policy.h`
- `fic-common/fic-core` runtime paths, `cmake/FicInstallLayout.cmake`
- `tests/CMakeLists.txt`, `docs/rollback.md`

## Validation

- `mutation_journal_tests`: 13/13 passed (exit 0).
- `rollback_executor_tests`: 20/20 passed (exit 0).
- `g++ -fsyntax-only` для всех изменённых TUs (включая `main.cpp`,
  `main_function.cpp`) — passed; собиралось вручную со сгенерированными
  headers из `build-alt-sss` (paths/version/ipc) + системные openssl/sqlite.
- `git diff --check` — passed.

## Remaining

- Изменения не закоммичены.
- Полный CMake build + full CTest не запускались: в окружении отсутствует
  dev-пакет libsystemd (`pkg-config libsystemd` недоступен), который требует
  `fic/CMakeLists.txt`; при доступном окружении прогнать
  `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=<...>` и full CTest.
- Ограничения MVP и unsupported-случаи описаны в `docs/rollback.md`.

