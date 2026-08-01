# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-01.
- Ветка: `main`.
- Базовый commit: `39aa722`.
- Текущая задача: первый versioned upgrade-контракт продукта, IPC,
  конфигураций и SQLite.
- Снимок описывает изменения задачи относительно указанного базового commit.

## Сделано

- Добавлен общий compile-time контракт `fic-version`: SemVer продукта и
  независимые версии административного IPC, конфигураций и device DB. Все пять
  исполняемых компонентов поддерживают `--version`; status API публикует
  относящиеся к компоненту версии.
- Административный IPC получил обязательный `api_version=1` в каждом запросе и
  ответе. Клиент добавляет версию автоматически и fail-closed отклоняет
  отсутствующую или несовместимую версию ответа.
- Все семь policy-конфигураций получили `_schema_version=1`. Новый
  `UpgradeManager` проверяет точную версию, выполняет offline-миграцию `0 -> 1`,
  заранее копирует полный набор конфигураций и использует атомарную запись.
- Добавлен `/opt/fic/state` и crash-resumable `upgrade.journal` с `flock`.
  Каждая попытка хранит отдельный каталог и финальный `manifest`; фазы:
  `prepared`, `config_migrated`, `database_migrated`, `committed`. Обычный
  daemon startup запрещен при незавершенной или чужой committed-версии.
- Device DB идентифицируется через `application_id=0x46494344` и
  `user_version=1`. Существующая БД больше не создается и не ремонтируется
  неявно при обычном запуске: структура, таблицы, индексы, revision triggers и
  canonical virtual roots должны точно соответствовать схеме.
- Реализована offline-миграция DB `0 -> 1`: согласованная копия через SQLite
  Backup API, `fsync`, запись пути backup в journal до начала транзакции,
  транзакционная миграция, `quick_check` и `foreign_key_check`. Из legacy БД
  удаляются только четыре неиспользуемые таблицы после полного backup.
- Новая установка создает schema 1 напрямую и больше не устанавливает
  `devices.seed.db`. Старый файл в `fic/src/scripts/db` оставлен только как
  реальный migration fixture и документирован как неустанавливаемый.
- Добавлены offline-команды `fic --maintenance begin-upgrade|migrate-config|
  check-config|commit-upgrade|wait-daemon` и `fic-dick --maintenance
  migrate-db|check-db`; обычные режимы обоих демонов проверяют journal и схемы.
- Поддерживаемые DEB/RPM builders встраивают package SemVer. `%pre`/`preinst`
  обоих daemon-пакетов останавливают службы до замены бинарников; основной
  post-install выполняет миграции, нормализует `root:fic` и read-only group
  modes, синхронизирует trust, запускает и health-checks оба сокета. Ошибка
  обязательного шага завершает package action ошибкой.
- Downgrade запрещен по SemVer и по версиям схем. Rollback определен как ручное
  восстановление согласованного config/DB backup с установкой точного прошлого
  комплекта пакетов. Remove не удаляет рабочую БД, journal, логи и backups и не
  делает рекурсивное удаление `/opt/fic`.
- Контракт и операторская процедура описаны в `docs/upgrade-contract.md`; README,
  архитектурные диаграммы, package docs и `AGENTS.md` синхронизированы.
- Добавлен `upgrade_contract_tests`: миграция legacy configs/DB, backup,
  interruption/resume, reinstall, rollback-set reconstruction, fresh install,
  downgrade/newer-schema refusal и структурная порча DB.

## Основные измененные файлы

- `fic-common/fic-version/`;
- `fic-common/fic-core/include/fic/core/UpgradeManager.h` и
  `fic-common/fic-core/src/UpgradeManager.cpp`;
- `fic-common/fic-device-db/{include/fic/device-db/DB.h,src/DB.cpp}`;
- `fic-common/fic-ipc/{include/fic/ipc/FicIpcClient.h,src/FicIpcClient.cpp}`;
- `fic/src/main.cpp`, `fic-dick/src/main.cpp`,
  `fic-dick/src/core/DeviceControlDaemon.cpp`;
- `fic/src/scripts/config/*.conf`, `cmake/FicInstallLayout.cmake`;
- `packaging/deb/build-fic-debian12-deb.sh`,
  `packaging/rpm/build-fic-alt-p11-rpm.sh`;
- `tests/upgrade/UpgradeContractTests.cpp`, IPC/path/static tests;
- `docs/upgrade-contract.md`, component/package README и
  `docs/architecture-diagrams.md`.

## Выполненные проверки

- Полная Release-конфигурация `alt-p11` с `FIC_PRODUCT_VERSION=0.1.0` в
  `/tmp/fic-upgrade-release`: успешно собраны все цели, включая `fic`,
  `fic-dick`, `fic-cli`, `fic-gui`, `fic-session-agent` и тесты.
- `ctest --test-dir /tmp/fic-upgrade-release --output-on-failure`: 24 теста,
  ошибок нет; sandbox-зависимые `ipc_transport_tests`, `admin_socket_tests` и
  root-зависимый неизмененный `command_hash_batch_tests` штатно пропущены.
- `ipc_transport_tests` и `admin_socket_tests` повторно запущены вне filesystem
  sandbox с временными Unix-сокетами: успешно.
- Все пять `--version` выводят product `0.1.0`; daemon/client schema и IPC
  версии соответствуют контракту `1`.
- CMake отклоняет невалидный SemVer `1.0.0-01`: успешно.
- `bash -n` для поддерживаемых Debian 12/13, Ubuntu 24.04 и ALT p11 package
  builders и Docker wrappers: успешно.
- Staged install CMake-компонента `fic` через `DESTDIR`: `/opt/fic/state`
  создается, legacy `devices.seed.db` отсутствует.
- `git diff --check`: успешно.
- Реальные `/run/fic`, `/opt/fic`, службы, политики и device state не
  изменялись.

## Что осталось

- На disposable VM собрать реальные DEB/RPM и выполнить полный package-manager
  сценарий: fresh install, upgrade с legacy state, принудительно прерванный
  upgrade/resume, ручной rollback согласованного backup и normal remove.
- После первого объявленного стабильного релиза поддерживаемые исходные версии
  схем и сроки поддержки нужно закреплять отдельно; сейчас реализован только
  переход pre-contract `0 -> 1`.
- Определить эксплуатационную retention/cleanup policy для каталогов
  `/opt/fic/state/upgrades` и `/opt/fic/state/db-backups`. Автоматическое удаление
  намеренно не добавлено, чтобы не уничтожать rollback provenance.

## Риски и решения

- Package lifecycle проверен статически и через staged install, но не под
  реальными `dpkg`/RPM/systemd транзакциями. До VM-прогона его нельзя считать
  подтвержденным на целевых ОС.
- Автоматический downgrade/rollback намеренно отсутствует: восстановление старых
  данных при оставшихся новых бинарниках создало бы mixed-version систему.
- Build metadata SemVer не участвует в precedence; reinstall той же версии
  создает новый transaction manifest и не затирает предыдущий backup provenance.
- Product upgrade journal защищает конфигурации и device DB. Он не делает
  multi-file применение политик к ОС crash-atomic; runtime policy transaction
  journal остается отдельной задачей.
