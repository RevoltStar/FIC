# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit corrective pass: `bd818ca`.
- Коммиты кода задачи: `c3faa48`, `ccfa815`, `514acb1`.

## Current task

- Закрыты четыре оставшихся PAM review finding: `local_users_only` subject
  scope, единый provider preflight/postcondition, generic required-capability
  topology safety и validation `PamProviderConfigTopology`.

## Accepted architecture / invariants

- Password-quality capability всех пяти profiles имеет explicit
  `AllPamSubjects`; `local_users_only` является `Ineffective` для
  `SecurityEffective`, включая `required_pam_enforcement`.
- `PamOptionPolicy` делегирует preflight единому provider semantic backend;
  pwquality prospective и final state используют один sequential evaluator.
- `pam_pwquality` для target libpwquality 1.4.5 вычисляется из native defaults,
  lexical `pwquality.conf.d/*.conf`, main config и argv каждой invocation.
- Invalid/unknown/unreadable/untrusted semantic input даёт `Broken`; валидные
  `enforcing=0` и `local_users_only` при `AllPamSubjects` дают `Ineffective`
  только в SecurityEffective.
- `PamOptionFile` остаётся raw mutation codec; успех возможен только после full
  effective provider postcondition. Положительные credits не служат
  доказательством policy `password_min_length`, потому что уменьшают реальную
  минимальную длину.
- Generic capability, option и flag одинаково fail-closed при активном
  unmanaged fallback/drop-in, кроме topology, заменённой explicit config.
- Platform validation проверяет normalized absolute paths, uniqueness,
  primary/config consistency, precedence, explicit semantics и compatibility
  topology с provider backend.
- File transaction использует optimistic snapshot validation и post-install
  observation, а не строгий atomic CAS против non-cooperating writers.

## Completed

- Добавлены typed subject scope и profile declarations для всех target
  distributions.
- Pwquality preflight учитывает immutable argv тем же evaluator'ом, включая
  SET-style flags и sequential duplicate options.
- Generic required capability проверяет unmanaged native topology.
- Добавлена fail-closed validation provider topology и regression tests.

## Changed areas

- `fic/src/modules/identity_access/pam/`.
- `fic/src/platform/` и пять platform profiles.
- PAM hierarchy/config и platform-profile tests.
- PAM architecture documentation.

## Validation

- Для Debian 12/13, Ubuntu 24.04/26.04 и ALT p11 собран target `fic`.
- На каждом из пяти profiles последовательно прошли 8/8 tests:
  `platform_profile_static_checks`, `pam_packaging_static_checks`,
  `pam_configuration_tests`, `passwdqc_config_file_tests`,
  `alt_pam_faillock_topology_tests`, `identity_policy_hierarchy_tests`,
  `platform_profile_tests`, `pam_policy_defaults_tests`.
- Configure использовал только pkg-config stub для отсутствующего на host
  `libsystemd`; `fic-session-agent` этой матрицей не собирался.
- Tests-first запуск воспроизвёл false-positive `local_users_only`, direct
  preflight divergence и отсутствие topology validation до production fix.
- `git diff --check` пройден; удалённые direct preflight helpers не найдены.

## Remaining

- Live `local_users_only` с non-local SSSD/LDAP identity не запускался:
  disposable identity-provider environment недоступен; unit/integration tests
  не выдаются за live proof.
- Live pwquality drop-in `enforce_for_root` и PAM argv override не завершены:
  повторный Docker run ранее был заблокирован лимитом внешнего выполнения.
- ALT live test не запускался; ALT daemon build и passwdqc regressions пройдены.
- Полная сборка всех executables и полный CTest не запускались; проверены daemon
  и непосредственно затронутые tests на всех profiles.
