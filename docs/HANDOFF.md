# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-07-30.
- Ветка: `main`.
- Базовый commit: `01cf97e`.
- Текущая задача: добавить базовый PAM-слой и пять политик авторизации.
- Реализация и локальная проверка завершены, изменения не зафиксированы commit.

## Сделано

- Добавлен daemon-модуль `AUTH` и пять отключенных по умолчанию политик:
  `password_min_length`, `password_min_classes`, `password_history_depth`,
  `failed_authentication_attempts` и
  `failed_authentication_unlock_time`.
- Реализован `PamConfiguration`, который строит effective-граф PAM-служб с
  учетом `@include`, `include` и `substack`, сохраняет источники и номера строк,
  ограничивает глубину/размер и fail-closed отклоняет циклы и
  неподдерживаемый синтаксис.
- Реализован provider-aware `PamProviderInspector`. Для lockout он распознает
  `pam_faillock`, `pam_tally2`, `pam_tally`; для password quality —
  `pam_pwquality`, `pam_passwdqc`, `pam_cracklib`; для history —
  `pam_pwhistory` и `pam_unix remember=`.
- Политики применяются только к уже активным `pam_faillock`,
  `pam_pwquality` и `pam_pwhistory`. Альтернативный или конфликтующий provider,
  отсутствие provider в одной из существующих целевых служб, дубли и
  неполный `pam_faillock` topology приводят к отказу без автоматической
  миграции PAM-стека.
- До и после записи проверяются все посещенные PAM service/include-файлы и
  используемые `.so`: обычный файл, владелец daemon owner (root в production),
  нет записи для group/other. Также проверяются `conf=` и аргументы PAM,
  перекрывающие управляемое значение.
- `PamOptionFile` атомарно обновляет только канонический provider-конфиг,
  сохраняет посторонние параметры и комментарии, исправляет все активные
  дубликаты ключа, отвергает symlink и проверяет результат. Отсутствующий файл
  создается с production-метаданными `root:root 0644`.
- В compile-time профили Debian 12/13, Ubuntu 24.04 и ALT p11 добавлены
  PAM search roots, module roots, целевые authentication/password services и
  канонические provider-конфиги. Данные профиля валидируются fail-closed.
- Добавлены `AUTH.conf`, русская и английская локализация, регистрация пяти
  классов в `init_policyMap()`, CMake/CTest-цель и упаковка `AUTH.conf` как
  Debian conffile / RPM `%config(noreplace)`.
- Обновлены `README.md`, `fic/README.md` и архитектурные диаграммы.

## Основные измененные файлы

- `fic/src/modules/auth/`
- `fic/src/platform/PlatformProfile.h`
- `fic/src/platform/PlatformCompatibility.cpp`
- `fic/src/platform/profiles/{Debian12,Debian13,Ubuntu2404,AltP11}Profile.cpp`
- `fic/src/core/main_function.{h,cpp}`
- `fic/src/scripts/config/AUTH.conf`
- `fic/src/scripts/lang/{ru,en}.lang`
- `fic/CMakeLists.txt`
- `tests/auth/PamConfigurationTests.cpp`
- `tests/platform/{PlatformProfileTests.cpp,static_checks.py}`
- `tests/CMakeLists.txt`
- `packaging/deb/build-fic-debian{10,11,12}-deb.sh`
- `packaging/rpm/build-fic-alt-p11-rpm.sh`
- `README.md`, `fic/README.md`, `docs/architecture-diagrams.md`

## Выполненные проверки

- `cmake -S . -B build-check -DFIC_TARGET_PLATFORM=alt-p11`: успешно.
- `cmake --build build-check -j1`: успешно, собраны все цели.
- `ctest --test-dir build-check --output-on-failure`: 17 тестов, ошибок нет;
  `admin_socket_tests` и root-зависимый `command_hash_batch_tests` штатно
  пропущены.
- Для `debian-12`, `debian-13` и `ubuntu-24.04` отдельно выполнены CMake
  configure, сборка `platform_profile_tests` и сам тест: успешно. ALT p11
  покрыт полной сборкой и полным CTest.
- PAM-тесты покрывают include-граф, цикл, конфликт `pam_faillock` с
  `pam_tally2`, неполный faillock topology, дубли provider, альтернативный
  `pam_unix remember=`, перекрывающий аргумент, небезопасные права `.so` и
  PAM-конфига, symlink option-файла и сохранение комментариев/посторонних
  значений.
- `git diff --check`: успешно.

## Что осталось

- Реальное применение AUTH-политик не выполнялось: оно изменяет
  `/etc/security/*.conf` и требует отдельной disposable VM для каждого
  дистрибутива/provider topology.
- Пакеты deb/rpm не собирались: тяжелые Docker/package builds для изменения
  исходной логики не запускались.
- Автоматическая установка provider-пакетов, создание PAM topology и миграция
  `pam_tally*`/`pam_passwdqc`/`pam_cracklib`/`pam_unix remember=` намеренно не
  входят в эту версию.

## Риски и решения

- Список целевых PAM-служб остается частью compile-time профиля. Отсутствующие
  службы пропускаются, но каждая существующая служба обязана пройти полную
  проверку; установка новой службы после FIC может превратить следующее
  применение в fail-closed ошибку до приведения ее PAM-стека в соответствие.
- Проверка `.so` подтверждает путь, тип, владельца и права, но пока не сверяет
  модуль с digest пакетной базы. Это отдельное возможное усиление trust-модели.
- `pam_pwquality minlen` имеет provider-native семантику: credit-параметры
  libpwquality могут влиять на фактическую проверку длины. Политика
  гарантирует значение `minlen`, а не полный аудит всех quality-настроек.
- PAM service-файлы не переписываются. Это сознательное ограничение: неверная
  автоматическая перестройка control stack опаснее безопасного отказа с
  диагностикой provider и источника.
