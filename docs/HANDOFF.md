# FIC handoff

## Current base

* branch: `main`
* base commit: `3f0e4b7d` + один коммит задачи (persistent crash-safe
  rollback shared `/etc/login.defs` backend)

## Current task

Persistent crash-safe rollback для пяти скалярных PASSWORD_AGING политик
`/etc/login.defs` и миграция двух USER_CREATION login.defs политик на новый
shared backend `IdentityLoginDefs`. Выполнено.

## Accepted architecture / invariants

* Ровно один FIC-контейнер `#@FIC_IDENTITY_LOGIN_DEFS_BLOCK_BEGIN version=1@`
  на `/etc/login.defs`, всегда в логическом EOF; sub-block
  `#@FIC_POLICY_BEGIN ref=MODULE/SUBMODULE/policy@` с одной canonical
  строкой `KEY value`. Whitelist ровно 7 политик (2 USER_CREATION +
  5 PASSWORD_AGING); journal payload `UndoRemoveIdentityLoginDefsManagedPolicy`
  — provenance only (без foreign значений/snapshot'ов);
  `previousAppliedLine` — только durable previous→target переход Prepared
  refresh.
* Строгая FIC-грамматика ≠ native consumer-семантика: shared
  `effectiveValue()` (last-wins, ведущие пробелы, комментарии, no-value
  игнорируется, target-like malformed — fail closed). `loadExpected()`
  operational политик обязан использовать его.
* Relation-валидация (`PASS_MIN_DAYS <= PASS_MAX_DAYS` при `MAX != -1`;
  `UID_MIN <= UID_MAX` в полном `uid_t`) — на native-effective состоянии
  кандидата, включая rollback-кандидат; invalid rollback relation —
  `Conflict` fail closed (без workaround'ов).
* Rollback = ownership release; последний released sub-block удаляет весь
  контейнер. Orphan sub-block / ручная правка owned строки / unknown FIC
  маркер — fail closed. Operational PASSWORD_AGING политики — NotEnrolled;
  неизвестные PASSWORD_AGING — Unsupported.
* USER_CREATION: `ConfigKind::LoginDefs` удалён; login.defs политики идут
  через shared backend, `/etc/default/useradd` и `/etc/adduser.conf` не
  изменены. MutationJournal schema_version не менялся (v2, как в Step 7E).

## Completed

* `MutationBackend::IdentityLoginDefs`, typed payload, serialize/deserialize,
  write/read parity validation, refresh guards (Prepared exact-match,
  RollbackFailed refuse, Applied previous-carry), fresh-with-previous reject,
  `normalizeIdentityLoginDefsPreparedToProvenState`.
* Shared backend `shared/login_defs/`: ManagedConfig (grammar, whitelist,
  effective reader, value/relation validation) + ManagedTransaction
  (apply/release/inspect, CAS, compensation, crash recovery).
* Rewired `LoginDefsOptionPolicy::apply()`, `loadExpected()`,
  `applyLoginDefsDefault()`; RollbackExecutor dispatch + enrollment +
  no-record guard (deps.passwordAgingPlatform).
* Tests: new `identity_login_defs_tests` (grammar/effective/apply/release/
  drift/crash/CAS/compensation/journal-guards/executor), обновлённые
  password_aging и user_creation suites.

## Changed areas

* `fic/src/rollback/`, `fic/src/modules/identity_access/shared/login_defs/`
  (новое), `password_aging/`, `user_creation/`, tests/CMakeLists.txt,
  `docs/rollback.md`, `docs/architecture-diagrams.md`.

## Validation

* Ubuntu 24.04 (host, build-check): полная сборка проекта, 0 errors/0
  warnings; 17/17 затронутых ctest зелёные.
* Debian 12, Debian 13, Ubuntu 26.04, ALT p11 (docker-контейнеры): сборка
  и запуск password_aging/user_creation/rollback_executor/
  identity_login_defs — PASS; `identity_login_defs_tests` PASS на всех.
* mutation_journal_tests: 4 fault-injection теста (persist failure через
  chmod) падают во ВСЕХ root-контейнерах — environmental (root игнорирует
  permissions), pre-existing, не связано с этим изменением.

## Remaining

* Полный CTest/E2E не запускался по scope задачи; runtime policy apply на
  хосте не выполнялся.
* Свежесозданный build-ubuntu2604/build-alt-p11 каталоги созданы для
  платформенной валидации (untracked build artifacts).
