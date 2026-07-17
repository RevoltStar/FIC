# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-07-17.
- Ветка: `main`.
- Базовый commit: `7f73165`.
- Текущая задача: план-оптимум рефакторинга захардкоженных product/runtime
  путей.

## Сделано

- Добавлен единый build-time layout `cmake/FicInstallLayout.cmake`. Config,
  data, logs, static assets, runtime и отдельные файлы остаются независимыми
  семантическими параметрами; универсальный `FIC_ROOT` намеренно не вводился.
- CMake генерирует `FicPathDefaults.h` и `FicIpcPathDefaults.h`. В C++ больше
  нет литералов `/opt/fic` и `/run/fic`.
- `FicProductPaths` валидирует абсолютные нормализованные пути, а
  `FicRuntimePaths` допускает однократную инициализацию неизменяемого контекста.
  Демоны инициализируют production layout при старте.
- Config, localization, logs, notify spool, lock status и command hash
  переведены на runtime paths. `ModuleConfigFileHandler` дополнительно умеет
  принимать явный каталог.
- `fic-device-db` больше не знает product layout. `DB` принимает `DBOptions`,
  а `fic-dick` строит их через собственный `DevicePaths`/`DeviceRuntimePaths`.
- Policy и device IPC получили разные endpoint-типы и переменные окружения:
  `FIC_SOCKET_PATH` и `FIC_DEVICE_SOCKET_PATH`.
- Создание обоих административных Unix-сокетов сведено в `FicAdminSocket`.
  Production-профиль проверяет `root:fic 0770` и socket `0660`, не заменяет
  чужой socket/обычный файл и удаляет только подтвержденный stale socket.
  Явный `--socket` использует development-профиль `0600`.
- systemd, tmpfiles, udev, notify dispatcher и XDG desktop переведены в
  CMake-шаблоны. GUI icon встроена в Qt resource.
- Добавлены install-компоненты `fic`, `fic-dick`, `fic-cli`,
  `fic-session-agent`, `fic-gui`. Debian 10/11/12 и ALT p11 staging используют
  эти компоненты вместо ручного копирования исходных integration-файлов.
  ALT отдельно передает каталоги systemd/tmpfiles.
- Добавлены тесты runtime layout, DBOptions, IPC endpoint и socket security, а
  также static check против возврата абсолютных product/runtime путей в C++ и
  обхода CMake layout упаковкой.
- Обновлены README компонентов, packaging и архитектурная документация.

## Основные измененные зоны

- `cmake/FicInstallLayout.cmake`, корневой и компонентные `CMakeLists.txt`.
- `fic-common/fic-core`: `FicRuntimePaths`, generated defaults и потребители
  product paths.
- `fic-common/fic-ipc`: endpoint defaults и `FicAdminSocket`.
- `fic-common/fic-device-db`: `DBOptions`.
- `fic`, `fic-dick`, `fic-cli`, `fic-gui`, `fic-session-agent`.
- `fic/src/scripts/*.in`, Debian/RPM build scripts.
- `tests/paths`, `tests/device-control/static_checks.py`.
- README и `docs/architecture-diagrams.md`.

## Проверки

Успешно выполнены:

```bash
cmake -S . -B /tmp/fic2-paths-build -DBUILD_TESTING=ON
cmake --build /tmp/fic2-paths-build -j2
ctest --test-dir /tmp/fic2-paths-build --output-on-failure

bash -n packaging/deb/build-fic-debian10-deb.sh
bash -n packaging/deb/build-fic-debian11-deb.sh
bash -n packaging/deb/build-fic-debian12-deb.sh
bash -n packaging/rpm/build-fic-alt-p11-rpm.sh
```

Собраны все цели, 7 тестов прошли. `admin_socket_tests` собран, но пропущен:
текущий sandbox запрещает `bind(AF_UNIX)` даже во временном каталоге с
`EPERM`. Install-компоненты `fic`, `fic-dick`, `fic-cli` и
`fic-session-agent` установлены в `/tmp/fic2-install-check`, состав файлов и
подстановки шаблонов проверены. Отдельная конфигурация с `/srv/fic/bin`,
`/etc/fic/policies` и `/var/run/fic-test` подтвердила согласованную генерацию
C++, systemd, tmpfiles и udev.

Реальные политики, device mutation, udev trigger, установка пакетов и запись в
`/opt/fic` не выполнялись. Docker-сборки deb/rpm не запускались.

## Что осталось и риски

- Перед merge желательно запустить `admin_socket_tests` вне sandbox и тяжелые
  Debian 12/ALT p11 package builds. В этой сессии их отсутствие не скрывается.
- Packaging lifecycle и Qt launcher по-прежнему относятся к фиксированному
  production-профилю `/opt/fic`; переносимый payload и integration templates
  управляются CMake, но создание совершенно нового дистрибутивного layout
  потребует отдельной адаптации maintainer scripts/launcher.
- Production socket startup теперь fail-closed, если группа `fic` отсутствует
  или metadata runtime-каталога нельзя привести к контракту. Это намеренное
  усиление безопасности, но старое некорректное окружение перестанет стартовать
  молча.
