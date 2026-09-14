# FIC: передача контекста

## Current base

- Ветка `main`, базовый commit `ab8f4bd` (HEAD).
- Рабочее дерево содержит незакоммиченные исправления оставшихся CI failures
  вокруг PAM faillock strategies, platform profile validation и тестовых PAM
  fixtures.

## Current task

- Закрыть оставшиеся CI failures после typed `pam_faillock` strategies:
  актуализировать валидатор platform profiles, Debian/Ubuntu profile data и
  targeted PAM tests без изменения runtime platform profiles services.

## Accepted architecture / invariants

- `enable_authentication_lockout.value`: `preauth_required` |
  `preauth_requisite` | `authsucc`; legacy `ENABLE` остаётся invalid.
- Debian/Ubuntu `AuthenticationLockout` pam-auth-update capability является
  strategy-aware: legacy `activationIdentifiers` пустой, а strategy recipes
  задаются через `strategyActivations`.
- Debian/Ubuntu platform profiles продолжают содержать superset PAM services
  (`sddm`, `gdm-password`, `lightdm` и т.д.); отсутствующие service-файлы
  фильтруются manager-side, а не удаляются из profiles.
- `PamControlFlowAnalyzer` должен считать терминальный
  `PAM_NEW_AUTHTOK_REQD` положительным исходом для trusted authentication
  bypass evidence так же, как обычный `success`.

## Completed

- `PlatformCompatibility` теперь валидирует strategy-aware pam-auth-update
  recipes отдельно от legacy activation identifiers и fail-closed отклоняет
  пустые, дублирующиеся или смешанные объявления.
- Debian12/Debian13/Ubuntu24.04/Ubuntu26.04 profiles больше не дублируют legacy
  faillock `activationIdentifiers` при наличии strategy recipes.
- PAM test fixtures приведены к валидным effective stacks для
  `preauth_required` и `authsucc`, включая account phase там, где она нужна
  для root-lockout semantics.
- `pam_capability_activation_policy_tests` сбрасывает policy value и fake
  pam-auth-update state между сценариями, чтобы проверка typed argv/idempotency
  не зависела от предыдущих блоков теста.
- `platform_profile_tests` проверяет пустой legacy recipe для strategy-aware
  faillock и полный набор strategy activation recipes.
- `PamControlFlowAnalyzer` учитывает positive terminal `new_authtok_reqd` при
  записи trusted bypass evidence.

## Changed areas

- `fic/src/platform/PlatformCompatibility.cpp`
- `fic/src/platform/profiles/Debian12Profile.cpp`
- `fic/src/platform/profiles/Debian13Profile.cpp`
- `fic/src/platform/profiles/Ubuntu2404Profile.cpp`
- `fic/src/platform/profiles/Ubuntu2604Profile.cpp`
- `fic/src/modules/identity_access/pam/PamControlFlowAnalyzer.cpp`
- `tests/fic/modules/identity_access/*`
- `tests/fic/platform/PlatformProfileTests.cpp`

## Validation

- Manual `PamCapabilityActivationPolicyTests.cpp` g++ build + run: PASSED.
- Manual `PamConfigurationTests.cpp` g++ build + run: PASSED.
- Manual `IdentityPolicyHierarchyTests.cpp` g++ build + run: PASSED.
- Manual direct-source `PlatformProfileTests.cpp` g++ build + run for current
  `ubuntu-24.04` profile: PASSED.
- `python3 tests/fic/platform/static_checks.py .`: PASSED.
- `python3 tests/common/static_checks.py .`: PASSED.
- `cmake --build build-check --target fic -j2`: PASSED.
- `ctest --test-dir build-check -N -R
  'pam_configuration_tests|pam_capability_activation_policy_tests|identity_policy_hierarchy_tests|platform_profile_tests'`:
  `Total Tests: 0`.
- `git diff --check`: PASSED.

## Remaining

- Full root CTest не запускался: текущий `build-check` не содержит test
  targets, а свежая root configure в этом окружении ранее упиралась в
  отсутствующий `gio-2.0` dev для `fic-session-agent`.
- Runtime PAM/login matrix не прогонялся; validation ограничена source/build
  тестами и статическими проверками.
- Коммит не создавать без отдельного запроса пользователя.
