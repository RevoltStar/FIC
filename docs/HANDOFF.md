# FIC: передача контекста

## Current base

- Ветка `main`, рабочее дерево содержит НЕ закоммиченные изменения
  (lift Debian 13 / Ubuntu 26.04 + gate-инфраструктура + тесты + docs).
- Baseline до задачи: `9f6137d173cc75d607f8dbdefcfb619bb060f345`
  (Step 6 follow-up и более ранние шаги — в нём).
- Коммит НЕ делать без явного запроса пользователя.

## Current task

**ReadOnly lift Debian 13 / Ubuntu 26.04 password topology** на базе real
functional evidence, полученной в одноразовых Docker-контейнерах
(`debian:13`, `ubuntu:26.04`; образы через `mirror.gcr.io` из-за Docker Hub
rate-limit). Без редизайнов: topology/Step 6/prerm/abstraction не менялись.

### Результаты (evidence matrix)

| Платформа | libpam | C2 G1–G11 | Wiring W1–W9 | Prerm (4 сцен.) | Options gate | Режим | Lift |
|---|---|---|---|---|---|---|---|
| Debian 12 | 1.5.2 | PASS | PASS | PASS (истор.) | PASS (O-flow) | ModuleArguments | был |
| Debian 13 | 1.7.0 | PASS | PASS | PASS 4/4 (28 PASS) | PASS (PC-flow) | ProviderConfigFile | ДА |
| Ubuntu 24.04 | 1.7.0 | PASS | PASS | PASS (истор.) | PASS (probe) | ProviderConfigFile | был |
| Ubuntu 26.04.1 | 1.7.0 | PASS | PASS | PASS 4/4 (28 PASS) | PASS (PC-flow) | ProviderConfigFile | ДА |

Ключевой факт: Debian 13 (в отличие от Debian 12) поставляет
`/etc/security/pwhistory.conf` — обе новые платформы остаются
`configurationMode=ProviderConfigFile`, БЕЗ module-argument evidence.
Lift = только `passwordTopologyRuntimeMutable = true` в профилях.

## Changed areas

- `fic/src/platform/profiles/Debian13Profile.cpp` — lift + evidence-комментарий.
- `fic/src/platform/profiles/Ubuntu2604Profile.cpp` — lift + evidence-комментарий.
- `fic/src/platform/profiles/Ubuntu2404Profile.cpp` — только комментарий
  (ссылка на lift 26.04).
- `tests/fic/platform/PlatformProfileTests.cpp` — пиннинги Debian 13 /
  Ubuntu 26.04 / Ubuntu 24.04 (mutable, ProviderConfigFile, no module-arg).
- `tests/fic/modules/identity_access/pam/PamPasswordWiringTests.cpp` —
  support contract для новых платформ (classic path, no module-arg evidence).
- `tests/integration/pam-c2/pam_c2_gate_driver.cpp` — команда `platform-mode`,
  `"-"` для empty options.
- `tests/integration/pam-c2/pam_c2_wiring_driver.cpp` — `platform-mode`,
  `provider-option` (перенесён из c2-драйвера).
- `tests/integration/pam-c2/pam_pwhistory_options_gate.sh` — distro case,
  mode-branch: O-flow (ModuleArguments) vs новый PC-flow (ProviderConfigFile:
  PC1–PC6 — production option-policy write в pwhistory.conf через
  `PamPasswordHistoryOptionPolicy::applyPam` + функциональные
  remember-window/enforce_for_root differentials).
- `tests/integration/pam-c2/pam_prerm_release_gate.sh` — debian-13 /
  ubuntu-26.04 distro cases.
- `tests/CMakeLists.txt` — источники wiring-драйвера (PamOptionPolicy,
  PamProviderConfigFile, PamPasswordHistoryOptionPolicy).
- `docs/rollback.md` — обновлён блок platform-семантики (4 lifted-платформы,
  PC-flow options gate как production provider-config evidence).

## Validation (фактически выполнено)

- Unit: `cmake -DFIC_TARGET_PLATFORM=debian-13` и `=ubuntu-26.04`
  (BUILD_TESTING=ON): build EXIT=0; CTest **107/107 PASS** на обеих
  (env-skip `command_hash_batch_tests`).
- Real Docker gates на ship-state (lift уже применён к профилям):
  - Debian 13: C2 PASS, wiring PASS, prerm 4/4 RC=0, options PC-flow PASS
    (включая функциональный enforce_for_root).
  - Ubuntu 26.04: C2 PASS, wiring PASS, prerm 4/4 RC=0, options PC-flow PASS.
- Regression (после изменений): Debian 12 C2 PASS, wiring PASS, options
  O-flow PASS; Ubuntu 24.04 C2 PASS.
- Пакеты: `dist/fic*0.1.0~rc.1_{debian13,ubuntu2604}_amd64.deb` собраны
  (нужны для prerm gates; staging-скрипты packaging/deb без изменений).
- `git diff --check` — clean.

## Remaining

1. Опционально: ubuntu-24.04 options gate (исторически PASS, не
   перегонялся).
2. Не коммитить без явного запроса.
