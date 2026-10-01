# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `bef88b7a7c5b7725109fd685307ece6849f2ee1f`.
- Текущий follow-up не закоммичен; коммит только по отдельному запросу.

## Current task

- Устранить несовместимость FIC с штатным PAM alias ALT Workstation 11.2/p11
  `/etc/pam.d/system-check-localuser` без ослабления общей symlink-защиты.
- Ручной `fic-cli policy apply IDENTITY_ACCESS all` на ВМ 10.88.0.86 дал
  23 applied, 5 failed, 3 disabled. Первичный отказ —
  `enable_authentication_lockout`: alias не был объявлен в `AltP11Profile`.
  Четыре `failed_authentication_*` отказали каскадно.

## Package evidence / accepted contract

- На ALT Workstation 11.2: `pam-config-1.10.0-alt0.p11.2.noarch` владеет
  `/etc/pam.d/system-check-localuser` (`rpm -qf`), observed link ведёт на
  `system-check-localuser-systemd`; `rpm -V pam-config` не показал изменения
  этого объекта.
- `pam-config` поставляет ровно два target-файла:
  `system-check-localuser-legacy` и `system-check-localuser-systemd`.
  `pam-config-control-1.10.0-alt0.p11.2` поставляет
  `/etc/control.d/facilities/system-check-localuser`; `control ... help`
  предлагает `legacy` и `systemd`. Control script выбирает существующие
  sibling-файлы `system-check-localuser-*`; для указанной package version
  доказаны только два штатных target. Wildcard trust в FIC не добавлен.
- Production trust остаётся typed: exact alias path + exact allowed targets +
  существующие safe filesystem checks в `PamConfiguration::resolveServicePath`.
  Пакетный `rpm` не используется для runtime trust.

## Completed / changed areas

- `fic/src/platform/profiles/AltP11Profile.cpp`: добавлен alias с exact
  targets `legacy` и `systemd`; generic resolver не менялся.
- `PlatformProfileTests`: проверяет полный список четырёх ALT aliases и
  exact targets нового alias; Debian/Ubuntu остаются без trusted aliases.
- `PamConfigurationTests`: оба target проходят через production resolver;
  unknown, absolute, parent escape, nested symlink, writable и directory
  target отклоняются. Добавлен opt-in read-only `--live-alt-alias`.
- `AltPamFaillockTopologyManagerTests`: SSS graph fixture использует
  `system-check-localuser -> system-check-localuser-systemd` и проходит
  enable/status/disable; opt-in `--live-alt-enable` проверяет native ALT
  topology в disposable container.
- `pam_provider_rollback_gate_alt.sh`: на обновлённом ALT p11 требует
  native alias и запускает оба production-backed probe; проверяет link,
  target contents/mode/owner и `rpm -V` для alias/targets до/после topology
  operation. Общий `rpm -V pam-config` после enable/disable может изменить
  timestamp управляемого `system-auth-local-only`, поэтому не сравнивается
  целиком.

## Validation

- Targeted build и CTest: `platform_profile_tests`,
  `pam_configuration_tests`, `pam_control_flow_analyzer_tests`,
  `alt_pam_faillock_topology_tests`, `identity_policy_hierarchy_tests` —
  5/5 PASS.
- `cmake --build build-check -j4` — PASS.
- Полный `ctest --test-dir build-check --output-on-failure` вне sandbox —
  114 passed, 1 skipped (`command_hash_batch_tests`, root-only).
  Первый sandbox run дал четыре environmental failures (source fixture,
  socket bind, group lookup); все четыре прошли вне sandbox.
- Real ALT gate в одноразовом `localhost/fic-rpm-builder:alt-p11` после
  обновления `pam-config` и `pam-config-control` с 1.9.1 до
  1.10.0-alt0.p11.2 — PASS, включая native alias resolver и реальный
  faillock enable/status/disable.

## Remaining

- Обновлённый FIC не устанавливался на ВМ 10.88.0.86: повтор исходного
  `fic-cli policy apply IDENTITY_ACCESS all` и четырёх зависимых option
  policies на ВМ не выполнен. Контейнерный manager gate подтверждает
  устранение исходной ошибки graph resolution, но не полный daemon/CLI path.
- Не менять PAM rollback architecture, generic symlink handling и unrelated
  modules. Не коммитить без отдельного запроса.
