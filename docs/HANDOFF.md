# FIC handoff

## Current base

* branch: `main`
* base commit: `eefc282` + два follow-up коммита (P1/P2 fixes shared
  login.defs rollback backend; operational PASSWORD_AGING lasting
  NotEnrolled lifecycle)

## Current task

Закрепление lasting lifecycle-контракта двух operational PASSWORD_AGING
политик (`password_aging_apply_to_existing_accounts`,
`password_aging_enforce_for_root`): намеренный и постоянный
`RollbackEnrollment::NotEnrolled` (non-reverting lifecycle), disable =
прекращение будущего enforcement с сохранением текущего `sp_min/sp_max/
sp_warn` аккаунтов; без per-user provenance, baseline, `chage` rollback,
нового backend или enum. Выполнено (код уже соответствовал контракту;
закреплён regression-тестами и документацией).

## Accepted architecture / invariants

* Ровно один FIC-контейнер `#@FIC_IDENTITY_LOGIN_DEFS_BLOCK_BEGIN version=1@`
  на `/etc/login.defs`, всегда в логическом EOF; sub-block
  `#@FIC_POLICY_BEGIN ref=MODULE/SUBMODULE/policy@` с одной canonical
  строкой `KEY value`. Whitelist ровно 7 политик; journal payload
  `UndoRemoveIdentityLoginDefsManagedPolicy` — provenance only.
* Единая таблица политик — header-only `IdentityLoginDefsPolicySpec.h`
  (policyName → submodule → key → value domain → relation); используют
  ManagedConfig, transaction и MutationJournal (writer/loader parity).
* UID relation — typed unsigned reader полного диапазона `uid_t`;
  missing/invalid UID peer — fail closed до мутации. PASS-пара — signed
  long + `PasswordAgingMissingKeySemantics` (только PASS_*).
* Prepared(target) recovery: recanonicalization ТОГО ЖЕ контейнера в EOF,
  завершение ТОЙ ЖЕ записи; никогда `Prepared(previous=target,
  target=target)`; third state / invalid relation — fail closed.
* No-record preflight (`inspectUnrecordedState`) доказывает когерентность
  всего shared домена через `proveCoherence`.
* Rollback = ownership release; invalid rollback relation — `Conflict`.
* Operational PASSWORD_AGING: намеренный non-reverting `NotEnrolled`
  lifecycle (disable останавливает будущий enforcement, сохраняет
  существующий account aging state; повторный apply disabled политики —
  `PolicyApplyStatus::Disabled`, `apply()`/`chage` не вызываются).
  Неизвестная PASSWORD_AGING политика — `Unsupported` (disable refused,
  никогда silent `NotEnrolled`). Пять scalar политик — `Supported`.

## Completed

* `tests/fic/rollback/RollbackExecutorTests.cpp`: enrollment matrix
  дополнена PASSWORD_AGING (5 scalar Supported, 2 operational NotEnrolled
  static+effective, future Unsupported); новый
  `testPasswordAgingOperationalNotEnrolledLifecycle` —
  `rollbackPolicyBeforeDisable` Success без journal/outcomes для обеих,
  production `disablePolicyAfterLookup` разрешён и не создаёт journal
  записей, unknown future политика refuses disable (Unsupported).
* `tests/fic/.../password_aging/PasswordAgingTests.cpp`: новый
  `testOperationalDisablePreservesAccounts` — disabled operational
  политики при periodic/manual apply возвращают Disabled, `chage` не
  вызывается (runner/reader счётчики == 0), значения shadow-аккаунтов не
  изменяются.
* `docs/rollback.md`: «в этой стадии остаются NotEnrolled» заменено на
  lasting contract (intentional non-reverting NotEnrolled lifecycle).

## Changed areas

* `tests/fic/rollback/RollbackExecutorTests.cpp`,
  `tests/fic/modules/identity_access/password_aging/PasswordAgingTests.cpp`,
  `docs/rollback.md`.

## Validation

* Ubuntu 24.04 (host, build-check): password_aging_tests,
  rollback_executor_tests (полный suite), identity_login_defs_tests,
  user_creation_tests — PASS.
* `git diff --check` — чисто.

## Remaining

* Полный CTest/E2E не запускался по scope задачи.
* Build-каталоги `build-*` — untracked artifacts.
