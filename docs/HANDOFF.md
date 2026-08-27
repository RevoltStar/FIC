# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `a96d91b9da27257538cceecb60e38b4ac45c96a8`.

## Current task

- Исправление logical/storage representation для policy values и поддержка
  явно переданного пустого значения в `fic-cli policy set`.

## Accepted architecture / invariants

- CLI и GUI работают только с logical representation.
- Daemon валидирует logical value; policy type выполняет logical -> storage и
  storage -> logical преобразования.
- `user_default_supplementary_groups` использует logical default `""`, но
  сохраняет пустой список как `[]`.
- `FIREWALL/custom_rules` сохраняет logical default `[]` и не изменяется.
- Наличие CLI value argument определяется по `argc`, а не по пустоте строки.

## Completed

- Исправлен logical default `GroupListPolicyTypeValue`.
- Policy descriptor serialization вынесена в testable `PolicyRegistryJson`.
- Daemon value mutation вынесена в `PolicyRegistryMutation`; `set` делегирует
  ей validation, serialization и atomic config path.
- CLI формирует `set_policy_value` request через testable helper, сохраняя
  явно переданное `""`.
- Добавлены regression tests для type round-trip, unset descriptor, daemon
  storage, CLI missing/empty argument и соседних empty-list policies.

## Changed areas

- `fic-cli/src/PolicySetCommand.*` и CLI routing;
- `fic/src/policy/registry/PolicyRegistryJson.*` и `PolicyRegistryMutation.*`;
- `GroupListPolicyTypeValue`;
- relevant CMake tests и static check.

## Validation

- Targeted build: `fic`, `fic-cli`, user creation, CLI, DAC, GRUB, registry и
  GUI service tests — успешно.
- Targeted CTest из 8 tests — успешно.
- Полная ALT p11 build — успешно.
- Полный CTest из 51 tests: 46 passed, 4 sandbox-skipped, 1 existing unrelated
  failure `ipc_protocol_validation_tests` (устаревшее ожидание reject API v1).
- Все static checks прошли.
- `git diff --check` — успешно перед финальным review.

## Remaining

- Изменения текущей задачи не закоммичены.
- Existing unrelated `ipc_protocol_validation_tests` failure не исправлялся.
