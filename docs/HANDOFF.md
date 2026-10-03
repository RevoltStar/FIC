# FIC handoff

## Current base

* branch: `main`
* base commit: `eefc282` (persistent crash-safe rollback shared
  `/etc/login.defs` backend) + один follow-up коммит задачи (P1/P2 fixes
  shared login.defs rollback backend)

## Current task

Исправление подтверждённых P1/P2 edge cases shared `/etc/login.defs`
rollback backend: full-`uid_t` UID relation, missing-UID-peer fail closed,
Prepared-target recanonicalization после внешнего append, no-record
whole-domain coherence, точная journal policy→key→value parity. Выполнено.

## Accepted architecture / invariants

* Ровно один FIC-контейнер `#@FIC_IDENTITY_LOGIN_DEFS_BLOCK_BEGIN version=1@`
  на `/etc/login.defs`, всегда в логическом EOF; sub-block
  `#@FIC_POLICY_BEGIN ref=MODULE/SUBMODULE/policy@` с одной canonical
  строкой `KEY value`. Whitelist ровно 7 политик; journal payload
  `UndoRemoveIdentityLoginDefsManagedPolicy` — provenance only.
* Единая таблица политик — header-only
  `IdentityLoginDefsPolicySpec.h` (policyName → submodule → key → value
  domain → relation). Её используют ManagedConfig (`policyRoute`,
  `validatePolicyValue`), transaction и MutationJournal payload validation —
  writer и loader не могут разойтись.
* UID relation (`UID_MIN <= UID_MAX`) — typed unsigned reader в полном
  диапазоне `uid_t` (без INT_MAX-капа); missing/invalid UID peer в
  effective состоянии кандидата — fail closed до мутации. PASS-пара —
  signed long + `PasswordAgingMissingKeySemantics` (только для PASS_*).
* Prepared(target) recovery после внешнего append: recanonicalization ТОГО
  ЖЕ когерентного контейнера в EOF (одна CAS, peer/foreign byte-exact,
  relation-пруф на кандидате) и завершение ТОЙ ЖЕ записи — никогда не
  создаётся `Prepared(previous=target, target=target)`; third state /
  invalid relation — fail closed.
* No-record preflight (`inspectUnrecordedState(path, policy, journal, err)`)
  доказывает когерентность всего shared домена через `proveCoherence`.
* Rollback = ownership release; invalid rollback relation — `Conflict`.
  Operational PASSWORD_AGING — NotEnrolled; неизвестные — Unsupported.

## Completed

* `IdentityLoginDefsPolicySpec.h` (единая таблица + canonical value
  validation); ManagedConfig/ManagedTransaction переведены на неё, дубль
  таблицы удалён.
* UID typed relation parse + missing-peer fail closed
  (`relationsValidInCandidate`).
* Prepared-target recanonicalization (`recanonicalizePreparedTarget` +
  restart apply после recovery).
* `inspectUnrecordedState` — journal + full-domain coherence; executor
  передаёт journal.
* MutationJournal: строгая policy→key→domain payload validation (writer +
  loader); убраны loose decimal/`identityLoginDefsPolicySubmodule`.
* Tests: новые `testUidRelationFullRange`,
  `testPreparedTargetRecanonicalization`, `testNoRecordSharedDomainCoherence`,
  `testJournalPolicyKeyParity`; `inspectUnrecordedState` вызовы обновлены.

## Changed areas

* `fic/src/modules/identity_access/shared/login_defs/` (новый
  `IdentityLoginDefsPolicySpec.h`, ManagedConfig, ManagedTransaction),
  `fic/src/rollback/MutationJournal.cpp`, `RollbackExecutor.cpp`,
  `tests/fic/.../IdentityLoginDefsTests.cpp`, `docs/rollback.md`.

## Validation

* Ubuntu 24.04 (host, build-check): сборка fic + identity_login_defs_tests,
  password_aging_tests, user_creation_tests, mutation_journal_tests,
  rollback_executor_tests, platform_profile_tests — все зелёные.
* Debian 12, Debian 13, Ubuntu 26.04, ALT p11 (docker): те же 5 тестов
  собраны и запущены — PASS.
* mutation_journal_tests: 4 pre-existing fault-injection chmod-фейла во
  всех root-контейнерах (root игнорирует permissions), на host — PASS.
* `git diff --check` — чисто.

## Remaining

* Полный CTest/E2E не запускался по scope задачи; runtime policy apply на
  хосте не выполнялся.
* Build-каталоги `build-*` — untracked artifacts.
