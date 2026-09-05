# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `ae1c800`.

## Current task

- Добавить exact trusted authentication bypass для штатного LightDM
  passwordless-login пути в ALT p11.

## Accepted architecture / invariants

- `PamControlFlowAnalyzer` остаётся fail-closed и принимает bypass только при
  точном совпадении service/module/control/argv/source с platform metadata.
- Несколько display manager могут объявлять отдельные exact bypass rules для
  одной группы из `passwordlessLoginControl`; generic whitelist не вводится.

## Completed

- ALT p11 profile содержит отдельные exact rules для `gdm-password` и
  `lightdm` с `pam_succeed_if.so user ingroup nopasswdlogin`.
- Platform validation разрешает несколько explicit passwordless rules, но
  требует хотя бы одно и проверяет argv каждого против управляемой группы.
- Добавлены profile и PAM control-flow regressions для LightDM и несовпадений
  service/source/control/argv.

## Changed areas

- ALT p11 platform profile и platform compatibility validation.
- `PlatformProfileTests` и `PamConfigurationTests`.

## Validation

- ALT p11 `pam_configuration_tests` — passed после полной пересборки target
  objects по существующим generated recipes.
- ALT p11 `platform_profile_tests` — passed при прямой сборке из актуальных
  profile sources.
- Обычный top-level CMake configure недоступен в текущем окружении: отсутствуют
  PAM и libsystemd development files.
- `git diff --check` выполняется перед завершением.

## Remaining

- Implementation work не осталось.
- Полная CMake/CTest validation не выполнялась из-за отсутствующих development
  dependencies; runtime-проверка на ALT p11 host не выполнялась.
