# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-01.
- Ветка: `main`.
- Базовый commit: `7295322`.
- Текущая задача: добавить конкретные политики SSSD, Kerberos и NSS поверх
  существующих typed configuration editors.
- Изменения рабочей копии не зафиксированы commit.

## Сделано

- Добавлена и зарегистрирована политика
  `sssd_offline_credentials_expiration`. Она принимает число дней `0..3650` и
  задаёт `[pam]/offline_credentials_expiration` в `sssd.conf`.
- Добавлен `SssdRuntime`. Для реально изменённого файла он через проверенный
  `systemctl` определяет активную службу `sssd.service`. Активная служба
  перезапускается и проверяется; неактивная не запускается. Ошибка restart
  включает rollback исходного файла и повторный restart с восстановленной
  конфигурацией.
- Добавлена и зарегистрирована политика `kerberos_ticket_lifetime`. Она
  принимает `60..86400` секунд и записывает значение с явным суффиксом `s` в
  `[libdefaults]/ticket_lifetime`. Существующие билеты не перевыпускаются.
- Добавлена и зарегистрирована fixed-политика `nss_local_accounts_first`. Она
  перемещает provider `files` в начало databases `passwd`, `group` и `shadow`,
  сохраняя порядок остальных providers и их NSS action blocks. Если `files`
  отсутствует, он добавляется. Отсутствующая database приводит к fail-closed
  ошибке.
- Все политики добавлены в `PolicyMap`, `IDENTITY_ACCESS.conf`, русскую и
  английскую локализацию, static architecture checks, README и диаграммы.
- Добавлены `identity_concrete_policies_tests`: успешный restart SSSD,
  compensating rollback после его ошибки, отсутствие запуска неактивного SSSD,
  преобразование Kerberos duration и сохранение NSS providers/actions.

## Основные измененные файлы

- `fic/src/modules/identity_access/submodules/sssd/SssdRuntime.{h,cpp}`
- `fic/src/modules/identity_access/submodules/sssd/policies/SssdOfflineCredentialsExpirationPolicy.{h,cpp}`
- `fic/src/modules/identity_access/submodules/kerberos/policies/KerberosTicketLifetimePolicy.{h,cpp}`
- `fic/src/modules/identity_access/submodules/nss/policies/NssLocalAccountsFirstPolicy.{h,cpp}`
- `fic/src/core/main_function.{h,cpp}`
- `fic/src/scripts/config/IDENTITY_ACCESS.conf`
- `fic/src/scripts/lang/{ru,en}.lang`
- `tests/identity_access/IdentityConcretePoliciesTests.cpp`
- `tests/CMakeLists.txt`
- `tests/platform/static_checks.py`
- `fic/README.md`
- `docs/architecture-diagrams.md`
- `docs/HANDOFF.md`

## Выполненные проверки

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=alt-p11`: успешно.
- `cmake --build build-check -j2`: успешно, собраны все цели.
- `ctest --test-dir build-check --output-on-failure`: 21 тест, ошибок нет;
  `admin_socket_tests` и root-зависимый `command_hash_batch_tests` штатно
  пропущены.
- `python3 tests/platform/static_checks.py .`: успешно.
- `git diff --check`: успешно.
- Для профиля `debian-13` отдельно выполнены configure, сборка `fic` и
  `identity_concrete_policies_tests`, затем запуск нового теста вместе с
  `platform_profile_tests`: успешно.
- Реальные `/etc/sssd/sssd.conf`, `/etc/krb5.conf`, `/etc/nsswitch.conf` и
  systemd-службы не изменялись: policy tests используют временные файлы и
  внедрённый command runner.
- Тяжелые deb/rpm package builds не запускались.

## Что осталось

- Runtime-проверка SSSD пока доказывает успешный restart и active-state, но не
  запрашивает effective option у самого SSSD: универсального интерфейса для
  чтения этого значения у daemon нет. Persistent postcondition проверяется
  повторным разбором полного main+snippet представления.
- `kerberos_ticket_lifetime` задаёт клиентский default/max request lifetime;
  KDC может выдать билет с меньшим сроком. Проверка KDC policy не относится к
  конфигурации локального клиента.
- NSS policy не проверяет наличие каждого стороннего provider `.so`, потому что
  она не добавляет и не переименовывает сторонние providers. Отдельный provider
  inspector нужен для политик, которые будут вводить конкретный источник.
- Реальные integration tests SSSD restart/authentication и Kerberos login
  требуют disposable VM для каждого поддерживаемого дистрибутива.

## Риски и решения

- Restart SSSD кратковременно прерывает responder/backend processes. Это
  обязательная цена немедленного применения: SSSD не перечитывает конфигурацию
  по SIGHUP. Политика отключена по умолчанию и restart выполняется только при
  реальном изменении активной службы.
- Между проверкой active-state и restart остаётся внешняя systemd race. Общий
  identity mutex защищает только FIC, а не администратора или другой daemon.
- Компенсирующая транзакция не обеспечивает crash-atomicity между atomic rename
  и restart. Для восстановления после падения процесса нужен transaction
  journal, которого пока нет.
- У проекта нет стабильных версий; compatibility aliases и миграции для новых
  политик не добавлялись.
