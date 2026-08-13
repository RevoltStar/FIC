# FIC: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-13.
- Ветка: `main`.
- Базовый commit: `ce27eb1`.
- Текущая задача: первая минимальная версия модуля FIREWALL на nftables.
- Реализация, локальная сборка и unit/static проверки завершены; изменения
  рабочей копии не зафиксированы commit.

## Сделано

- Добавлен модуль `FIREWALL` с четырьмя Policy:
  `block_rdp`, `block_ftp`, `custom_rules`, `exclusive_firewall_control`.
  Три status-only Policy не имеют `.value` и отвергают `policy set`;
  `custom_rules` хранит нормализованный JSON.
- Добавлена строгая модель `FirewallRule`: incoming/outgoing, tcp/udp/any,
  IPv4/IPv6 address/CIDR, одиночный порт, строковый диапазон `first-last`,
  allow/block. Неизвестные поля, смешанные IP family, порты вне `1..65535` и
  порты при protocol any отклоняются.
- Каждая обычная firewall Policy владеет отдельной `inet` table
  `fic_block_rdp`, `fic_block_ftp` или `fic_custom_rules`; base chains имеют
  `policy accept`. Скрипты проходят `nft -c -f -` и затем применяются через
  `nft -f -` одним batch без временного файла.
- `ProcessOptions` получил optional `standardInput`; `ProcessExecutor` пишет
  stdin из отдельного потока, одновременно читая stdout/stderr и сохраняя
  существующий timeout/kill process-group contract.
- В каждый platform profile добавлен обязательный `ExecutableId::Nft` с
  `/usr/sbin/nft`. Debian/Ubuntu package `fic` зависит от `nftables`, ALT RPM —
  от пакета `nftables`; package trust sync автоматически включает новый путь.
- Daemon startup/periodic pass исключает FIREWALL из generic per-policy loop и
  выполняет один отдельный full reconciliation. Он читает все четыре статуса,
  удаляет stale FIC-owned tables и атомарно пересоздаёт полный desired state.
  Отдельного состояния модуля нет; все Policy DISABLE дают пустой managed
  firewall state.
- Обычный IPC apply одной FIREWALL Policy не изменён и затрагивает только её
  table. Apply enabled `exclusive_firewall_control` нейтрализует только чужие
  base chains `inet`/`ip`/`ip6`, `filter`/`route`, hooks input/output.
- Exclusive mode очищает и пересоздаёт только влияющую base chain с прежними
  family/table/name/type/hook/priority и `policy accept`. Целые таблицы, NAT,
  FORWARD, bridge, netdev и остальные цепочки не меняются. После DISABLE
  удалённые сторонние правила автоматически не восстанавливаются.
- Добавлен `FIREWALL.conf`, обе локализации, upgrade config manifest,
  документация архитектуры/daemon, changelog, packaging dependencies и tests.

## Основные изменённые файлы

- `fic/src/modules/firewall/{FirewallRule,FirewallNft,FirewallBackend,FirewallPolicies}.{h,cpp}`;
- `fic/src/core/main_function.{h,cpp}`, `fic/src/main.cpp`;
- `fic-common/fic-core/{include/fic/core/ProcessExecutor.h,src/ProcessExecutor.cpp,src/UpgradeManager.cpp}`;
- `fic/src/platform/PlatformProfile.h`, `PlatformExecutableResolver.cpp` и все
  пять profile implementations;
- `fic/src/scripts/config/FIREWALL.conf`, `fic/src/scripts/lang/{ru,en}.lang`;
- Debian/Ubuntu и ALT package builders;
- `tests/firewall/`, `tests/CMakeLists.txt`, platform/upgrade tests;
- `README.md`, `fic/README.md`, `docs/architecture-diagrams.md`, `CHANGELOG.md`
  и этот файл.

## Выполненные проверки

- `cmake -S . -B /tmp/fic-firewall-build -DFIC_TARGET_PLATFORM=debian-12 -DCMAKE_BUILD_TYPE=Debug` — успешно.
- `cmake --build /tmp/fic-firewall-build -j2` — полная сборка успешно, включая
  `fic`, `fic-cli`, `fic-gui`, `fic-session-agent`, `fic-dick` и все test targets.
- `ctest --test-dir /tmp/fic-firewall-build --output-on-failure -E '^(release_contract_tests|platform_profile_tests)$'` — 28 passed, 3 host-dependent skipped, ошибок нет.
- `firewall_tests`, `firewall_static_checks`, `upgrade_contract_tests` и
  `platform_profile_static_checks` отдельно успешно выполнены.
- `platform_profile_tests` собран для `debian-13`, `ubuntu-24.04`,
  `ubuntu-26.04`, `alt-p11`; ALT p11 executable успешно выполнен. Debian 12
  profile входит в полную сборку.
- `bash -n` для изменённых DEB/RPM builders — успешно.
- `git diff --check` — успешно до финального обновления HANDOFF.

## Ограничения и известные проблемы

- В build host отсутствует executable `nft`. Поэтому реальные `nft -c`,
  применение ruleset и integration test в отдельном network namespace не
  выполнялись. Host firewall намеренно не изменялся. Синтаксис/JSON-модель
  покрыты unit tests, но runtime integration остаётся обязательной проверкой на
  disposable VM/namespace с nftables.
- Full reconciliation v1 всегда заменяет существующие FIC-owned tables, а не
  строит rule-by-rule diff. Операция семантически идемпотентна и атомарна, но
  меняет nft handles. Между read-only inspection, `nft -c` и apply остаётся
  гонка с внешним firewall manager; конфликт приводит к ошибке, а следующий
  periodic pass повторяет reconciliation.
- Exclusive mode намеренно разрушителен для содержимого выбранных чужих host
  base chains и не имеет rollback/backup. Он сохраняет таблицу и остальные
  chains, но внешнему firewall manager может потребоваться повторная загрузка
  своей конфигурации после DISABLE.
- `platform_profile_tests` имеет подтверждённый baseline рассинхрон уже в
  `HEAD`: тест ожидает два allowed target для Debian/Ubuntu `/etc/resolv.conf`,
  а профили содержат третий `/usr/lib/systemd/resolv.conf`. Полный CTest дал
  единственную эту ошибку; FIREWALL-файлы её не меняют.
- `release_contract_tests` отдельно запущен и завершился известной несвязанной
  ошибкой `Expected 20 release packages, found 25`. Package artifacts и Docker
  DEB/RPM builds не создавались.
