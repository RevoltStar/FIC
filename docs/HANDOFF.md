# FIC: передача контекста

## Current base

- Дата: 2026-08-23.
- Ветка: `main`.
- Базовый commit задачи: `acee755`.

## Current task

- Semantic control-flow verification обязательных PAM enforcement mechanisms
  и policy `required_pam_enforcement`.

## Accepted architecture / invariants

- `PamConfiguration` остаётся единственным PAM parser: прежний flat view
  сохранён, а structured effective stack сохраняет границы `substack`.
- `PamControlFlowAnalyzer` моделирует Linux-PAM simple/extended controls,
  numeric jumps, `include`, `substack`, `done`, `die`, `ignore` и `reset`.
- Неизвестные PAM modules моделируются недетерминированно; если отсутствие
  successful bypass нельзя доказать, verification завершается fail-closed.
- Каждая обычная PAM policy сама проверяет собственную capability. Новая
  policy не является dependency declaration и не provision/remediate PAM.
- Верхнеуровневый результат остаётся `PolicyApplyStatus::Failed`; конкретные
  enforcement state, violation kind и path передаются через captured logs.

## Completed

- Добавлены состояния `Missing`, `Inactive`, `Ineffective`, `Broken`,
  `Conflicting`, `Effective` и общий `PamCapabilityVerifier`.
- Существующие `PamOptionPolicy` требуют semantic effectiveness до записи и
  повторно проверяют её после записи.
- Добавлена и зарегистрирована текстовая policy `required_pam_enforcement`
  для `pam_faillock`, `pam_pwquality`, `pam_pwhistory` со строгим разбором,
  trim, дедупликацией и отказом для пустых/неизвестных элементов.
- Добавлены bypass diagnostics с source line, module result, control/action и
  bounded symbolic state/transition/trace limits.
- Обновлены default config, ru/en localization и PAM architecture contract.

## Changed areas

- `fic/src/modules/identity_access/submodules/pam/` и новая PAM policy;
- PolicyRegistry registration, `IDENTITY_ACCESS.conf`, localization;
- PAM/unit/policy/static tests и `docs/architecture-diagrams.md`.

## Validation

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=ubuntu-24.04` — успешно.
- `cmake --build build-check -j2` — полный build успешно, включая daemon, CLI,
  GUI, session agent, device daemon и tests.
- Целевые `pam_configuration_tests`, `identity_policy_hierarchy_tests`,
  `platform_profile_static_checks` — успешно.
- Полный `ctest --test-dir build-check --output-on-failure`: 36 passed,
  4 sandbox-dependent skipped; 1 известный несвязанный failure
  `ipc_protocol_validation_tests` на assertion для status request.
- `git diff --check` — успешно до финального обновления HANDOFF.

## Remaining

- Реальное применение PAM policies и изменение host PAM stack намеренно не
  выполнялись; нужна staging-проверка на поддерживаемых platform profiles.
- Analyzer моделирует documented outcomes известных providers и все outcomes
  неизвестных modules, но не анализирует машинный код и не оценивает силу
  provider options как отдельную password/lockout policy.
- Несвязанный `ipc_protocol_validation_tests` в scope задачи не исправлялся.
