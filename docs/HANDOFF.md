# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей незакоммиченной правки: `3451499`.

## Current task

- Исправлен security defect manager-first orchestration в
  `PamCapabilityActivationPolicy`.

## Accepted architecture / invariants

- `PamTopologyManager::inspect()` является authoritative решением о
  strategy-specific topology/ownership state и всегда выполняется до решения
  об успехе или activation.
- `Enabled` не мутируется; `Disabled` проходит через `canEnable()`/`enable()`;
  `Broken` и `Unavailable` завершаются fail-closed без mutation.
- После успешного `enable()` manager повторно инспектируется и должен вернуть
  `Enabled`; затем для любого успешного пути выполняется независимая fresh
  Structural verification actual PAM graph.
- Generic activation policy не содержит distro-specific branching и не
  отключает topology.

## Completed

- Удалён initial Structural early-return, обходивший topology manager.
- Добавлены различимые diagnostics для inspection/state/activation и
  structural postcondition failures.
- Regression покрывает manager state flow, post-enable re-inspection,
  `StaticVerifyOnly`, `PamAuthUpdate` idempotence/broken state и ALT external
  `pam_faillock`/`pam_pwhistory` ownership без mutation.
- Обновлено authoritative архитектурное описание manager/verifier split.

## Changed areas

- `fic/src/modules/identity_access/pam/policies/PamCapabilityActivationPolicy.cpp`.
- `tests/fic/modules/identity_access/pam/PamCapabilityActivationPolicyTests.cpp`.
- `docs/architecture-diagrams.md`.

## Validation

- Targeted suite из activation/configuration/ALT topology/hierarchy/planner и
  static/packaging checks: 9/9 passed.
- PAM-focused CTest: 8/8 passed.
- Disposable Debian 12 container: configure, target build и activation policy
  test passed.
- Disposable ALT p11 container: configure и target build passed; executable
  test passed напрямую (`ctest` в builder image отсутствует).
- Full local CTest запущен: PAM/identity/static checks passed; общий результат
  неполный из-за 11 отсутствующих executable в partial build и независимого
  `fic_gui_license_info` Qt plugin failure.
- Full local build и target `fic` ограничены отсутствующими host headers
  `systemd/sd-login.h`/`systemd/sd-daemon.h`.

## Remaining

- Package-install/live PAM mutation smoke для этой orchestration-only правки не
  выполнялся; deterministic filesystem fixtures и два distro containers
  покрывают целевые state transitions без изменения PAM хоста.
- Коммит не создавать без отдельного явного запроса пользователя.
