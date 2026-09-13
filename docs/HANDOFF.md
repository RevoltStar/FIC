# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `34ab2cb` (HEAD); рабочее дерево содержит
  незакоммиченные follow-up исправления fail-closed ownership/external
  detection для pam-auth-update стратегии.

## Current task

- Follow-up исправления `enable_authentication_lockout`: не менять
  архитектуру трёх стратегий, а закрыть оставшиеся fail-open cases в
  pam-auth-update ownership/external-topology detection, поправить описание
  `preauth_required`, корректно обрабатывать отсутствующие optional PAM
  services из platform-profile superset.

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
  + generated `common-*` при любой post-mutation ошибке. Ownership analysis,
  unreadable state DB и external-graph inspection errors fail-closed. Rollback
  failure диагностируется как CRITICAL.
- ALT `authsucc` хранит original `pam_tcb` auth rule в anchor marker и
  `buildDisabledContent()` восстанавливает original bytes как из preauth
  block, так и из authsucc anchor.
- `PamControlFlowAnalyzer` учитывает `authsuccDenied` в symbolic-state
  identity и имеет negative coverage для RecoverableFailureAccounting,
  PrematureSuccessAccounting, authsucc-denial bypass paths, and typed SDDM
  root subject exclusions.

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
- `PamAuthUpdateTopologyManager` получил tri-state external inspection
  (`Clear`/`Present`/`Error`), recursive detection of `pam_faillock` inside
  substacks, fail-closed pam-auth-update state DB reads, and an unconditional
  `Enabled && !manageable` mutation guard.
- `PamAuthUpdateTopologyManager` теперь фильтрует `services_` через
  `PamConfiguration::existingServices()` перед external `pam_faillock`
  inspection и uniform-strategy detection: absent candidate services
  (`gdm-password`/`lightdm` на SDDM-only host) игнорируются, пустой набор и
  ошибки резолва остаются fail-closed.
- `PamAuthUpdateTopologyManagerTests.cpp` расширен targeted regression cases:
  nested external faillock, malformed effective stack, invalid state DB, and
  unmanaged enabled topology mutation refusal, plus missing candidate PAM
  services during `preauth_required` activation/inspection.
- RU/EN description `enable_authentication_lockout` исправлен: для
  `preauth_required` final denial comes from remembered required auth failure,
  while account `pam_faillock` is for success accounting/reset.
- Добавлена модель trusted authentication exclusions, Debian12/13 SDDM
  root exclusion declaration, policy `disable_root_sddm_login`, wiring в
  daemon policy list, RU/EN/default config entries и targeted tests.
- `disable_root_sddm_login` writes the hardened SDDM gate
  `auth requisite pam_succeed_if.so user != root quiet_success`; Debian-native
  `control=required` remains declared as the distribution form and is upgraded
  in place to `requisite`. CFG analysis treats both `required` and enforced
  `requisite` controls as the same typed subject exclusion, with `requisite`
  recorded on `die` control flow.
- ALT topology test targets that compile `PamControlFlowAnalyzer.cpp` now also
  compile `PamOptionFile.cpp`; the analyzer reads canonical pam_faillock config
  flags through `PamOptionFile::hasFlag()`, so omitting that source caused CI
  linker failures.

## Changed areas

- `fic/src/modules/identity_access/pam/` (pam-auth-update manager, ALT
  manager, CFG analyzer, activation policy, SDDM root-login policy)
- `packaging/deb/pam-configs/*`, `packaging/deb/README.md`
- `fic/README.md`, `ru.lang`, `en.lang`
- `fic/src/platform/PlatformProfile.h`
- `fic/src/platform/profiles/Debian12Profile.cpp`,
  `fic/src/platform/profiles/Debian13Profile.cpp`
- `fic/src/daemon/main_function.*`
- `fic/src/resources/config/IDENTITY_ACCESS.conf.in`
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
- Manual `PamAuthUpdateTopologyManagerTests.cpp` g++ build + run after
  follow-up fail-closed changes: PASSED
- Manual `PamAuthUpdateTopologyManagerTests.cpp` g++ build + run after
  missing-candidate service filtering: PASSED
- `git diff --check`: PASSED
- `git diff --check`: PASSED after SDDM enforced-control follow-up.
- Manual `AltPamPasswordHistoryTopologyManagerTests.cpp` g++ build + run after
  linker fix: PASSED (`SKIP wrong-gid mutation` on this filesystem).
- Manual `AltPamFaillockTopologyManagerTests.cpp` g++ build + run after linker
  fix: PASSED.
- `git diff --check`: PASSED after ALT topology test linker fix.

## Remaining

- Full root CTest was not run in this WSL checkout; root configure is known to
  require missing `gio-2.0` dev for `fic-session-agent`.
- `cmake --build build-check --target pam_auth_update_topology_tests -j2`
  could not run because `build-check` has no tests target; the existing
  `build-check-container` cache points at `/src`; a fresh `/tmp` configure
  still fails on missing `gio-2.0`. Targeted validation was therefore done via
  manual g++ build of the `pam_auth_update_topology_tests` source set.
- Full runtime PAM matrix from the prompt is not complete. Only Debian13
  structural pam-auth-update generation was verified live. Debian12,
  Ubuntu 24.04/26.04 and ALT p11 runtime login/tally/reset behavior remain
  deferred to suitable disposable environments.
- Additional provider runtime topologies (`pam_sss`, `pam_ccreds`) were not
  exercised live; analyzer/unit fixtures cover symbolic ordering risks.
- Коммит не создавать без отдельного запроса пользователя.
