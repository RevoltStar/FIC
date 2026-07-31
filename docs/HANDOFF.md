# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-07-31.
- Ветка: `main`.
- Базовый commit: `d636ae4`.
- Текущая задача: зафиксировать pre-stable политику проекта по обратной
  совместимости и миграциям.
- Реализация `IDENTITY_ACCESS/{PAM,SSSD,KERBEROS,NSS,COMPOSITE}` находится в
  базовом commit. Текущие изменения документации не зафиксированы commit.

## Сделано

- В `AGENTS.md` зафиксировано, что у проекта пока нет стабильных версий.
  Миграции конфигов и схем БД, compatibility aliases, dual-read/dual-write и
  поддержка старых API/runtime formats по умолчанию не реализуются. Вместо
  этого все актуальные producers/consumers, seed-данные, packaging, тесты и
  документация переводятся на новый формат одновременно. Правило действует до
  отдельного объявления стабильной версии или явного требования задачи.
- Модуль и runtime-конфиг переименованы из `AUTH` в `IDENTITY_ACCESS`.
  Пять существующих политик сохранены без изменения строковых имен и перенесены
  в подмодуль `PAM`:
  `password_min_length`, `password_min_classes`, `password_history_depth`,
  `failed_authentication_attempts` и
  `failed_authentication_unlock_time`.
- Добавлен общий `IdentityAccessPolicy`, который владеет module metadata,
  загружает `IDENTITY_ACCESS.conf` и предоставляет единый mutex для всех
  изменений identity-конфигурации внутри daemon.
- Добавлены template-method базы `PamPolicy`, `SssdPolicy`,
  `KerberosPolicy` и `NssPolicy`. Их final `apply()` один раз получает и
  валидирует policy value, берет общий mutex и передает значение typed hook.
  Реальные редакторы и конкретные политики пока существуют только для PAM.
- PAM infrastructure перенесена в
  `fic/src/modules/identity_access/submodules/pam/`, namespace заменен на
  `fic::identity::pam`. Provider-aware поведение, PAM graph verification и
  атомарная запись канонического provider-конфига не изменены.
- Добавлен `CompositePolicy`. Он не содержит вложенные `Policy`, а владеет
  `ConfigurationParticipant`: каждый participant выполняет read-only preflight
  и возвращает полностью подготовленный `PreparedConfigurationChange`.
- `ConfigurationTransaction` последовательно выполняет commit всех persistent
  изменений, persistent verification, runtime activation и effective
  verification. При ошибке реально измененные и неуспешно начатые шаги
  восстанавливаются в обратном порядке, rollback проверяется, а recovery errors
  не скрывают первичную ошибку.
- Для будущих participants зафиксирован контракт защиты от внешнего изменения:
  перед commit требуется сравнение с подготовленным snapshot, а rollback не
  должен перезаписывать более позднюю правку администратора или package tool.
- `DomainNamePolicy` и другие фиктивные composite/SSSD/Kerberos/NSS политики не
  добавлялись по требованию задачи.
- Синхронизированы `PolicyMap`, `IDENTITY_ACCESS.conf`, русская и английская
  локализация, Debian/RPM conffile manifests, README и архитектурные диаграммы.
- Добавлены тесты hierarchy/template-method contract, composite preflight и
  компенсирующей транзакции. Они покрывают success, no-op, commit/persistent
  verify/activation/effective verify failures, partial attempts, reverse
  rollback, runtime restoration, `changed=false`, recovery errors и исключения.

## Основные измененные файлы

- `AGENTS.md`
- `docs/HANDOFF.md`

## Выполненные проверки

- Для текущего документационного изменения: `git diff --check`.
- Проверки реализации `IDENTITY_ACCESS` ниже относятся к базовому commit
  `d636ae4`:
- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=alt-p11`: успешно.
- `cmake --build build-check -j2`: успешно, собраны все цели.
- `ctest --test-dir build-check --output-on-failure`: 19 тестов, ошибок нет;
  `admin_socket_tests` и root-зависимый `command_hash_batch_tests` штатно
  пропущены.
- Для `debian-12`, `debian-13` и `ubuntu-24.04` отдельно выполнены CMake
  configure, сборка `fic`, `pam_configuration_tests`,
  `identity_policy_hierarchy_tests`, `platform_profile_tests` и запуск этих
  трех тестов: успешно для всех профилей.
- `python3 tests/platform/static_checks.py .`: успешно.
- `git diff --check`: успешно.
- Архитектурный и rename/install аудит отдельными read-only ревью: блокирующих
  замечаний после исправлений нет.

## Что осталось

- Для SSSD, Kerberos и NSS еще нет configuration editor API и конкретных
  политик. Нынешние классы задают границу и единый lifecycle, но не подменяют
  будущую реализацию парсеров `/etc/sssd/sssd.conf`, `/etc/krb5.conf` и
  `/etc/nsswitch.conf`.
- Нет ни одной конкретной composite-политики. Первая такая политика должна
  реализовать subsystem-specific participants, а не вызывать leaf `Policy`.
- Реальное применение PAM-политик не выполнялось: оно изменяет
  `/etc/security/*.conf` и требует disposable VM для каждого дистрибутива и
  provider topology.
- Пакеты deb/rpm не собирались: тяжелые Docker/package builds не запускались.
- Автоматическая установка provider-пакетов, создание PAM topology и миграция
  `pam_tally*`/`pam_passwdqc`/`pam_cracklib`/`pam_unix remember=` намеренно не
  входят в эту версию.

## Риски и решения

- У проекта нет стабильных версий, поэтому `AUTH` -> `IDENTITY_ACCESS` и
  последующие изменения форматов выполняются как чистая замена без alias и
  миграций. Не следует добавлять совместимость с промежуточными состояниями
  репозитория без отдельного требования. После объявления стабильной версии
  эту стратегию необходимо пересмотреть.
- Composite обеспечивает compensating rollback, но не crash-atomicity набора
  файлов. Падение процесса между двумя atomic rename потребует transaction
  journal и recovery при старте daemon; такого журнала пока нет.
- Общий mutex сериализует только операции текущего процесса FIC. Participants
  обязаны сверять snapshot непосредственно перед commit/rollback, чтобы не
  затереть конкурентную правку администратора или package manager.
- PAM service-файлы не переписываются. Альтернативный или конфликтующий
  provider и неверная topology по-прежнему приводят к fail-closed ошибке, а не
  к опасной автоматической перестройке PAM stack.
