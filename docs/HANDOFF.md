# FIC: передача контекста

## Current base

- Дата: 2026-08-23.
- Ветка: `main`.
- Базовый commit задачи: `e474dc2`.

## Current task

- Общий декларативный механизм Required/Recommended dependencies между FIC
  policies. Реальные production dependencies и `login.defs` намеренно не
  входят в текущую итерацию.

## Accepted architecture / invariants

- `PolicyRegistry` остаётся storage; scheduling выполняет отдельный
  `PolicyExecutionPlanner`. `std::map` и status enum не менялись.
- Dependency metadata создаётся constructor-time, замораживается при
  регистрации и задаётся полным `module:submodule:policy` reference.
- Candidate registry заменяет действующий только после проверки missing,
  self, duplicate/mixed-strength dependencies и cycles любого strength.
- Disabled policy не раскрывает dependency graph. Required non-Applied
  dependency блокирует dependent как Failed; Recommended создаёт WARN
  diagnostic и не блокирует собственный `Policy::apply()`.
- Dependency policies никогда автоматически не ENABLE. Shared dependency
  выполняется один раз; hard-excluded module не возвращается через graph edge.
- Успех request определяется requested roots. Dependency-only results остаются
  видимыми в `PolicyApplySummary`, но Failed Recommended dependency не делает
  успешную single root policy неуспешной.

## Completed

- В `fic-policy` добавлены `PolicyRef`, dependency strength/metadata,
  constructor helpers и requested-root metadata в summary.
- Добавлены fail-closed graph validation, `PolicyExecutionPlanner` и единый
  `PolicyApplication` layer для single/module/all/excluded scopes.
- `apply_policy` теперь возвращает весь multi-result summary без скрытого
  применения dependencies; daemon JSON и CLI уже поддерживают массив results.
- Добавлены dummy-policy tests для Required/Recommended, disabled pruning,
  transitive/mixed chains, shared nodes, exclusions, deterministic ordering,
  immutable metadata, request/batch success и invalid/cyclic graphs.

## Changed areas

- `fic-common/fic-policy/`;
- `fic/src/core/` и daemon single-apply routing;
- core/registry tests и dependency architecture documentation.

## Validation

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=ubuntu-24.04` — успешно.
- Target build `policy_execution_planner_tests`, `module_registry_tests`,
  `fic`, `fic-cli`, `policy_service_tests` — успешно.
- Целевые planner/registry/GUI-service tests — 3/3 успешно.
- `cmake --build build-check -j2` — полный build всех компонентов успешно.
- Полный CTest: 38 passed, 4 environment-dependent skipped; новый test прошёл.
  Один воспроизводимый несвязанный failure: `ipc_protocol_validation_tests`
  assertion для status request.
- `git diff --check` — успешно до финального обновления HANDOFF.

## Remaining

- Production policies пока не объявляют dependencies; mechanism проверен только
  dummy-policy unit tests, без host mutations.
- `login.defs` и password aging остановлены до отдельной следующей задачи; ни
  один связанный handler/policy/config не добавлялся.
- Несвязанный `ipc_protocol_validation_tests` в scope задачи не исправлялся.
