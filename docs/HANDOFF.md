# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit review-задачи: `d83e955`.
- Коммиты задачи: `c136ab7`, `8261cb9`, `1f72c7b`.

## Current task

- Закрыты release-blocking PAM review findings: effective semantics
  `pam_pwquality`, provider config topology/fallback metadata и точное описание
  optimistic snapshot transaction guarantee.

## Accepted architecture / invariants

- `PamCapabilityVerifier` делегирует Structural/SecurityEffective проверку
  единому provider semantic backend; policy layer не знает provider filesystem
  topology или grammar.
- `pam_pwquality` для target libpwquality 1.4.5 вычисляется из native defaults,
  lexical `pwquality.conf.d/*.conf`, main config и argv каждой invocation.
- Invalid/unknown/unreadable/untrusted semantic input даёт `Broken`; валидный
  final `enforcing=0` даёт `Ineffective` только в SecurityEffective.
- `PamOptionFile` остаётся raw mutation codec; успех возможен только после full
  effective provider postcondition. Положительные credits не служат
  доказательством policy `password_min_length`, потому что уменьшают реальную
  минимальную длину.
- Provider/platform topology отдельно выражает primary, fallbacks, drop-ins,
  precedence и explicit-config semantics. Generic provider fail-closed при
  активном unmanaged fallback/drop-in, пока нет полного evaluator.
- File transaction использует optimistic snapshot validation и post-install
  observation, а не строгий atomic CAS против non-cooperating writers.

## Completed

- Добавлены typed `PwqualityEffectiveState`, native config/argv evaluator и
  centralized Pwquality/Passwdqc/Generic semantic backend dispatch.
- Ordinary pwquality policies и `required_pam_enforcement` используют один
  security-effective contract; проверяются все services/invocations.
- Учтены SET flags, integer clamps, signed credits, main/drop-in/argv ordering,
  malformed/unknown inputs и target-version отсутствие `pam_pwquality conf=`.
- Аудит target metadata зафиксировал native `/etc/security` primary paths;
  fallback lists faillock/pwhistory/pwquality для текущих profiles пусты.
- CAS contract и оставшееся rename race window документированы без ложного
  заявления об atomic compare-and-swap.

## Changed areas

- `fic/src/modules/identity_access/pam/`.
- PAM provider/platform metadata.
- PAM hierarchy/config/topology/default tests и их CMake wiring.
- Atomic writer/transaction contract comments и PAM architecture docs.

## Validation

- Для Debian 12/13, Ubuntu 24.04/26.04 и ALT p11 собран target `fic`.
- На каждом из пяти profiles последовательно прошли 8/8 tests:
  `platform_profile_static_checks`, `pam_packaging_static_checks`,
  `pam_configuration_tests`, `passwdqc_config_file_tests`,
  `alt_pam_faillock_topology_tests`, `identity_policy_hierarchy_tests`,
  `platform_profile_tests`, `pam_policy_defaults_tests`.
- Configure использовал только pkg-config stub для отсутствующего на host
  `libsystemd`; `fic-session-agent` этой матрицей не собирался.
- В disposable Debian 13 и Ubuntu 26.04 containers с libpwquality 1.4.5:
  baseline FIC minlen/required apply прошёл, weak password отклонён, strong
  принят; при `enforcing=0` обе FIC проверки отклонены как ineffective, а weak
  password принят warning-only. Containers удаляемые, host PAM не менялся.
- `git diff --check` пройден; stale `defaultConfigPath`,
  `verifyInvocationSemantics` и `pam_pwquality.so conf=` не найдены.

## Remaining

- Live drop-in `enforce_for_root` и PAM argv override сценарии не завершены:
  повторный Docker run заблокирован лимитом внешнего выполнения.
- ALT live weak/strong test не запускался по той же причине; ALT daemon build и
  passwdqc regressions пройдены статически/тестами.
- Полная сборка всех executables и полный CTest не запускались; проверены daemon
  и непосредственно затронутые tests на всех profiles.
- Между последней snapshot precondition и `rename(2)` остаётся узкое TOCTOU
  окно против arbitrary non-cooperating writer; post-install observation
  обнаруживает только часть таких гонок.
