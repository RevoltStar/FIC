# FIC: передача контекста

## Current base

- Дата: 2026-08-24.
- Ветка: `main`.
- Базовый commit задачи: `38c1596`.

## Current task

- Инфраструктура conditional `Required`/`Recommended` policy dependencies
  без её подключения к конкретным production policies.

## Accepted architecture / invariants

- `PolicyDependencyCondition` является declarative metadata с типами
  `Always` и `OwnerValueEquals`; owner — policy, объявившая dependency.
- Несовпадение или отсутствие owner value делает ребро неактивным
  без target result, diagnostic, block или warning.
- Disabled owner не раскрывает dependencies. Structural graph validation
  учитывает все рёбра независимо от conditions.
- Один owner может объявить только одно ребро к target; literal
  `OwnerValueEquals` валидируется типом owner policy fail-closed.

## Completed

- Добавлены condition metadata, helper `whenOwnerValueEquals` и перегрузки
  `addRequiredDependency`/`addRecommendedDependency`; старый API остался
  unconditional.
- Отдельный evaluator подключён к planner и registry validation.
- Добавлены tests всех обязательных conditional scenarios; обновлено
  authoritative архитектурное описание.

## Changed areas

- `fic-common/fic-policy/`;
- daemon dependency graph/planner;
- `tests/core/PolicyExecutionPlannerTests.cpp`;
- `docs/architecture-diagrams.md`.

## Validation

- `cmake -S . -B build-hardening-ubuntu2404 -DFIC_TARGET_PLATFORM=ubuntu-24.04`
  — успешно.
- `cmake --build build-hardening-ubuntu2404 --target policy_execution_planner_tests -j2`
  и targeted CTest — успешно.
- `cmake --build build-hardening-ubuntu2404 -j2` — вся сборка успешна.
- Full CTest: 39 passed, 4 environment-dependent skipped; один известный
  unrelated failure `ipc_protocol_validation_tests` для `status`.
- `git diff --check` — успешно.

## Remaining

- Production policies на conditional dependencies намеренно не переводились.
- Реальное policy apply и изменения host state не запускались.
