# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `310a33d` (HEAD); рабочее дерево содержит
  незакоммиченную corrective-реализацию трёх стратегий pam_faillock.

## Current task

- Исправление реализации `enable_authentication_lockout` после
  `de86d56599087e35c87c3309f8ee8ec467e74ef1`: сохранить стратегический дизайн
  (`preauth_requisite`, `preauth_required`, `authsucc`), закрыть rollback,
  ownership, CFG-анализ, ALT round-trip и Debian/Ubuntu placement blockers.

## Accepted architecture / invariants

- `enable_authentication_lockout.value`: `preauth_required` |
  `preauth_requisite` | `authsucc`; legacy `ENABLE` не мигрируется и остаётся
  invalid/fail-closed.
- Debian/Ubuntu используют compositional pam-auth-update profiles:
  один selector (`fic-faillock-notify`, `fic-faillock-preauth-required` или
  `fic-faillock-authsucc`) плюс общий `fic-faillock-authfail`.
- Selector profiles конфликтуют только между собой; `fic-faillock-authfail`
  не конфликтует с selectors, иначе pam-auth-update удаляет `authfail` из
  generated stack.
- `fic-faillock-authsucc` — `Auth-Type: Additional`, `required`, без account
  phase. Primary authsucc запрещён: successful Primary providers могут
  перепрыгнуть его numeric jump'ом.
- `PamAuthUpdateTopologyManager` распознаёт FIC ownership по pam-auth-update
  state DB, отказывается мутировать external valid topology, проверяет
  одинаковую strategy по всем target services и rollback'ит snapshot state DB
  + generated `common-*` при любой post-mutation ошибке. Rollback failure
  диагностируется как CRITICAL.
- ALT `authsucc` хранит original `pam_tcb` auth rule в anchor marker и
  `buildDisabledContent()` восстанавливает original bytes как из preauth
  block, так и из authsucc anchor.
- `PamControlFlowAnalyzer` учитывает `authsuccDenied` в symbolic-state
  identity и имеет negative coverage для RecoverableFailureAccounting,
  PrematureSuccessAccounting и authsucc-denial bypass paths.

## Completed

- Исправлены Debian pam-config conflicts: `authfail` стал shared profile,
  selectors конфликтуют только между собой.
- Исправлены/дописаны unit tests:
  `PamControlFlowAnalyzerTests.cpp`,
  `PamAuthUpdateTopologyManagerTests.cpp`,
  ALT pairwise/idempotency/authsucc round-trip coverage.
- Исправлены test fixtures: explicit `conf=<tmp>/security/faillock.conf`,
  correct snapshot config directory, test isolation/reset, valid external
  topology account phase.
- Проверен Debian13 generated pam-auth-update output в disposable Docker image:
  во всех трёх стратегиях `authfail` присутствует; для `authsucc` generated
  order: `pam_unix success=2` -> `pam_faillock authfail` -> `pam_deny` ->
  `pam_permit` -> Additional `pam_faillock authsucc`; account phase не содержит
  `pam_faillock`.

## Changed areas

- `fic/src/modules/identity_access/pam/` (pam-auth-update manager, ALT
  manager, CFG analyzer, activation policy)
- `packaging/deb/pam-configs/*`, `packaging/deb/README.md`
- `fic/README.md`, `ru.lang`, `en.lang`
- `tests/CMakeLists.txt`
- `tests/fic/modules/identity_access/pam/*`
- `tests/integration/packaging/PamPackagingChecks.py`

## Validation

- `cmake --build build-check --target fic -j2`: PASSED
- Manual `PamControlFlowAnalyzerTests.cpp` g++ build + run: PASSED
- Manual `PamAuthUpdateTopologyManagerTests.cpp` g++ build + run: PASSED
- Manual `AltPamFaillockTopologyManagerTests.cpp` g++ build + run: PASSED
- `python3 tests/integration/packaging/PamPackagingChecks.py .`: PASSED
- `python3 tests/fic/platform/static_checks.py .`: PASSED
- `python3 tests/common/static_checks.py .`: PASSED
- Debian13 Docker structural generation using local
  `fic-pam-lab-v7:debian13`: PASSED for generated `common-auth` /
  `common-account` shape described above.
- `git diff --check`: PASSED

## Remaining

- Full root CTest was not run in this WSL checkout; root configure is known to
  require missing `gio-2.0` dev for `fic-session-agent`.
- Full runtime PAM matrix from the prompt is not complete. Only Debian13
  structural pam-auth-update generation was verified live. Debian12,
  Ubuntu 24.04/26.04 and ALT p11 runtime login/tally/reset behavior remain
  deferred to suitable disposable environments.
- Additional provider runtime topologies (`pam_sss`, `pam_ccreds`) were not
  exercised live; analyzer/unit fixtures cover symbolic ordering risks.
- Коммит не создавать без отдельного запроса пользователя.
