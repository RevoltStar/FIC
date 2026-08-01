# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-08-01.
- Ветка: `main`.
- Базовый commit: `b814b3d`.
- Текущая задача: реализовать редакторы конфигураций SSSD, Kerberos и NSS.
- Изменения рабочей копии не зафиксированы commit.

## Сделано

- Добавлены три независимых typed editor API. Универсальный INI-редактор не
  используется, поскольку грамматика и effective semantics у подсистем
  различаются.
- `SssdConfiguration` редактирует секции и options существующего основного
  `sssd.conf`, нормализует дубликаты целевой option, сохраняет посторонние
  строки и читает `.conf` snippets. Каталоги snippets обрабатываются в
  заданном порядке, файлы внутри каждого — лексикографически. Определение
  изменяемого ключа в snippet приводит к fail-closed ошибке до записи.
- `KerberosConfiguration` редактирует scalar relations верхнего уровня,
  сохраняет relation/section final markers и вложенные subsections. Read-only
  preflight обходит абсолютные `include`/`includedir` с лимитами глубины и
  числа файлов, проверяет циклы и порядок файлов. Конфликтующее определение в
  included profile и profile `module` приводят к fail-closed ошибке.
- `NssConfiguration` парсит и сериализует typed списки NSS services и action
  blocks с обычными и negated status expressions, обновляет все дубликаты
  целевой database и сохраняет комментарии и посторонние databases.
- Общий `PreparedFileChange` читает только существующие regular files,
  проверяет owner/group/mode/размер и запрещает symlink во всей цепочке
  каталогов. Commit повторно сверяет snapshot, пишет через `AtomicFileWriter`,
  проверяет результат и не затирает позднюю внешнюю правку при rollback.
- `SssdPolicy`, `KerberosPolicy` и `NssPolicy` теперь владеют соответствующим
  редактором и передают его в typed apply-hook. Options конструктора позволяют
  policy/test/platform layer задавать пути и требования к metadata.
- Добавлены тесты синтаксиса, сохранения постороннего содержимого, дубликатов,
  SSSD snippet precedence, Kerberos include graph/final markers/module/cycles,
  NSS actions, unsafe metadata и symlinks, no-op, snapshot race и безопасного
  rollback.
- Обновлены README, архитектурные диаграммы и static architecture checks.

## Основные измененные файлы

- `fic/src/modules/identity_access/configuration/PreparedFileChange.{h,cpp}`
- `fic/src/modules/identity_access/submodules/sssd/SssdConfiguration.{h,cpp}`
- `fic/src/modules/identity_access/submodules/kerberos/KerberosConfiguration.{h,cpp}`
- `fic/src/modules/identity_access/submodules/nss/NssConfiguration.{h,cpp}`
- `fic/src/modules/identity_access/submodules/{sssd,kerberos,nss}/*Policy.{h,cpp}`
- `tests/identity_access/IdentityConfigurationEditorsTests.cpp`
- `tests/identity_access/IdentityPolicyHierarchyTests.cpp`
- `tests/CMakeLists.txt`
- `tests/platform/static_checks.py`
- `fic/README.md`
- `docs/architecture-diagrams.md`
- `docs/HANDOFF.md`

## Выполненные проверки

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=alt-p11`: успешно.
- `cmake --build build-check -j2`: успешно, собраны все цели.
- `ctest --test-dir build-check --output-on-failure`: 20 тестов, ошибок нет;
  `admin_socket_tests` и root-зависимый `command_hash_batch_tests` штатно
  пропущены.
- `python3 tests/platform/static_checks.py .`: успешно.
- `git diff --check`: успешно.
- Для профиля `debian-13` отдельно выполнены configure, сборка `fic`,
  `identity_configuration_editors_tests`, `identity_policy_hierarchy_tests` и
  запуск этих двух тестов вместе с `platform_profile_tests`: успешно.
- Реальные `/etc/sssd/sssd.conf`, `/etc/krb5.conf` и `/etc/nsswitch.conf` не
  изменялись; тесты используют временные деревья.
- Тяжелые deb/rpm package builds не запускались.

## Что осталось

- Конкретных зарегистрированных политик SSSD, Kerberos, NSS и Composite пока
  нет. Редакторы предоставляют основу для них, но сами не являются `Policy`.
- File-level `set*()` не перезапускает SSSD, не инвалидирует кеши и не
  выполняет другие runtime-действия. Runtime-sensitive composite participant
  должен обернуть подготовленное изменение и реализовать activation/effective
  verification/restore.
- Kerberos API пока намеренно не редактирует вложенные dictionary relations
  (`[realms]`, `[capaths]` и подобные структуры). Для них нужен отдельный typed
  API, а не расширение scalar setter строковым путём.
- SSSD snippets учитываются при effective read, но редактор не выбирает и не
  переписывает произвольный snippet автоматически. Policy должна явно владеть
  выбранным файлом, если появится необходимость управлять drop-in.
- Реальные integration tests требуют disposable VM/контейнеров с SSSD и
  Kerberos для каждого поддерживаемого дистрибутива.

## Риски и решения

- У проекта нет стабильных версий; compatibility aliases и миграции для этой
  реализации не добавлялись.
- Компенсирующая транзакция не обеспечивает crash-atomicity набора файлов.
  Падение между atomic rename требует отдельного transaction journal, которого
  пока нет.
- Общий mutex сериализует только операции текущего процесса FIC. Snapshot
  checks защищают от тихого затирания внешней правки, но полная защита от
  переименования каталогов конкурентным привилегированным процессом потребует
  перехода всего write path на `openat`/directory descriptors.
- Редакторы работают с форматом конфигурации, а не проверяют наличие или ABI
  NSS/SSSD/Kerberos shared libraries. Проверка provider/package availability —
  отдельная задача platform/provider inspector.
