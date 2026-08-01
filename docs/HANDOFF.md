# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-01.
- Ветка: `main`.
- Базовый commit: `f37c5c1`.
- Текущая задача: удалить небезопасную политику
  `nss_local_accounts_first`.
- Изменения рабочей копии не зафиксированы commit.

## Сделано

- Полностью удалены `NssLocalAccountsFirstPolicy.{h,cpp}`.
- Политика удалена из `init_policyMap()` и daemon headers.
- Удалены seed-настройка `nss_local_accounts_first`, русская и английская
  локализация. Compatibility alias и миграция не добавлялись: стабильных
  релизов у проекта нет.
- Удалены policy-specific тест, static checks и CMake source entry.
- README и архитектурные диаграммы больше не заявляют эту политику.
- Базовый `NssPolicy`, `NssConfiguration` и тесты NSS-редактора сохранены: они
  не навязывают порядок providers и остаются основой для будущей
  provider-aware политики.
- Причина удаления: универсальное перемещение `files` перед всеми источниками
  нарушает distro-specific семантику. В ALT `shadow` должен сохранять `tcb`
  перед `files`; в системах с `compat` простая перестановка может обойти
  `+/-` и `*_compat` semantics.

## Основные измененные файлы

- удалены
  `fic/src/modules/identity_access/submodules/nss/policies/NssLocalAccountsFirstPolicy.{h,cpp}`;
- `fic/src/core/main_function.{h,cpp}`;
- `fic/src/scripts/config/IDENTITY_ACCESS.conf`;
- `fic/src/scripts/lang/{ru,en}.lang`;
- `tests/identity_access/IdentityConcretePoliciesTests.cpp`;
- `tests/CMakeLists.txt`;
- `tests/platform/static_checks.py`;
- `fic/README.md`;
- `docs/architecture-diagrams.md`;
- `docs/HANDOFF.md`.

## Выполненные проверки

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=alt-p11`: успешно.
- `cmake --build build-check -j2`: успешно, собраны все цели.
- `ctest --test-dir build-check --output-on-failure`: 21 тест, ошибок нет;
  `admin_socket_tests` и root-зависимый `command_hash_batch_tests` штатно
  пропущены.
- `python3 tests/platform/static_checks.py .`: успешно.
- `git diff --check`: успешно.
- Реальные системные конфигурации и службы не изменялись.
- Тяжелые deb/rpm package builds не запускались.

## Что осталось

- Конкретных NSS-политик сейчас нет.
- Если политика запрета удалённых identity providers будет реализована позже,
  она должна использовать platform/provider classification, отдельно
  обрабатывать `tcb`, `compat`, `role`, `systemd`, неизвестные providers и
  generators вроде authselect/nsswitch-config. Blacklist только из `sss`,
  `ldap`, `winbind` недостаточен.
- Реальные integration tests SSSD restart/authentication и Kerberos login
  требуют disposable VM для каждого поддерживаемого дистрибутива.

## Риски и решения

- `sssd_offline_credentials_expiration` и `kerberos_ticket_lifetime` остаются
  зарегистрированными и не затронуты удалением NSS-политики.
- NSS editor по-прежнему допускает typed изменение providers, но конкретная
  политика обязана доказать distro-specific effective semantics до записи.
- У проекта нет стабильных версий, поэтому старый конфигурационный ключ удалён
  без compatibility alias и миграции.
