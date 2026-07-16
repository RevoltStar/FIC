# FIC 2.0: передача контекста

Этот файл хранит текущее состояние работы между чатами. Он не является журналом
всей разработки и не заменяет `AGENTS.md` или архитектурную документацию.

## Текущий снимок

- Обновлено: 2026-07-16.
- Ветка: `main`.
- Базовый commit: `7a1fdad`.
- Текущая задача: поддержка активного include-графа sudoers, политика запрета
  запуска sudo без аутентификации и общий контракт безопасной записи файлов.

## Сделано

- Добавлен `SudoersConfiguration`, который начинает с `/etc/sudoers`, раскрывает
  `@include`, `#include`, `@includedir` и `#includedir` в порядке sudoers,
  обнаруживает циклы и сохраняет координаты источника.
- Существующие политики глобальных `Defaults` переведены на эффективное значение
  всего графа. Исправление записывается в `/etc/sudoers.d/zzzz-fic`, после чего
  проверяется, что managed-файл действительно определяет итоговое значение.
- Добавлена политика `sudo_require_authentication`. Она заменяет активные
  `NOPASSWD` на `PASSWD`, `!authenticate` на `authenticate` и активный
  `exempt_group` на `!exempt_group` непосредственно в файле-источнике.
- Составные строки с несколькими `Host_Spec` и многострочные нарушающие правила
  обрабатываются fail-closed: FIC предварительно проверяет весь граф, сообщает
  источники и не изменяет ни один файл при наличии неоднозначной конструкции.
- Исправлено ложное распознавание составного `Host_Spec` для валидной комбинации
  Runas-группы и command option: `(ALL:ALL) CWD=/tmp NOPASSWD: ...` теперь
  корректно переписывается. Двоеточия внутри Runas-скобок не считаются
  разделителями Host_Spec.
- При ошибке записи, `visudo`, перечитывания или проверки постусловия политика
  откатывает все уже измененные sudoers-источники, а не только последний файл.
- `AtomicFileWriter` стал общей реализацией атомарной записи с `fsync` файла и
  каталога. Он поддерживает сохранение метаданных существующего файла либо
  принудительное применение заданных `uid`/`gid`/режима.
- `FileHandler` и его основные наследники принимают `FileHandlerOptions`.
  Создание отсутствующего файла по умолчанию запрещено как при чтении, так и
  при сохранении; это также закрывает удаление файла между load/save.
- Явное создание и метаданные настроены для `/etc/sysctl.conf` (`0644`,
  `root:root`), записи конфигурации display manager (`0644`, `root:root`),
  `commandhash.txt` (`0660`, `root:<group of /opt/fic/db>`) и managed sudoers
  (`0440`, `root:root`). Чистое чтение файлов больше не создает их.
- Перед изменением и после него запускается `visudo -c -f`; production-запуск
  проходит через `VerifiedProcessExecutor`. Для применения политик требуется
  зарегистрированный hash `/usr/sbin/visudo` либо `/usr/bin/visudo`.
- Удален старый неиспользуемый однофайловый sudoers-парсер из `Sudo.h` и
  отладочная функция `test()` с жестко заданным домашним путем.
- Добавлены CTest-тесты include-порядка, managed override и отката, точечного
  исправления аутентификации, идемпотентности, циклов, отсутствующих include,
  symlink-защиты, сложных fail-closed случаев, многострочных правил,
  синтаксически некорректных правил и реального `visudo` на временном файле.
  Отдельный набор проверяет создание, запрет создания, metadata policy, symlink
  и удаление между load/save для `FileHandler`.
- Обновлены конфигурация политики, русская/английская локализация, README и
  архитектурная схема.
- CMake-фильтры тестовых `.cpp` в `fic`, `fic-gui` и `fic-dick` ограничены
  именем файла. Подстрока `test` в абсолютном пути исходного дерева больше не
  исключает production-исходники.

## Измененные файлы

- `fic-common/fic-core/include/fic/core/AtomicFileWriter.h`
- `fic-common/fic-core/src/AtomicFileWriter.cpp`
- `fic-common/fic-core/include/fic/core/FileHandler.h`
- `fic-common/fic-core/src/FileHandler.cpp`
- `fic-common/fic-core/include/fic/core/ConfigFileHandler.h`
- `fic-common/fic-core/src/ConfigFileHandler.cpp`
- `fic-common/fic-core/include/fic/core/MultilineConfigFileHandler.h`
- `fic-common/fic-core/src/MultilineConfigFileHandler.cpp`
- `fic-common/fic-core/include/fic/core/SectionConfigFileHandler.h`
- `fic-common/fic-core/src/SectionConfigFileHandler.cpp`
- `fic-common/fic-core/include/fic/core/SingleLineFileHandler.h`
- `fic-common/fic-core/src/SingleLineFileHandler.cpp`
- `fic-common/fic-core/src/CommandHashStore.cpp`
- `fic-common/fic-core/CMakeLists.txt`
- `fic/src/modules/dac/submodules/Sudo.h`
- `fic/src/modules/dac/submodules/Sudo.cpp`
- `fic/src/modules/dac/submodules/sudo/SudoersConfiguration.h`
- `fic/src/modules/dac/submodules/sudo/SudoersConfiguration.cpp`
- `fic/src/modules/dac/submodules/sudo/DAC_sudo_require_authentication.h`
- `fic/src/modules/dac/submodules/sudo/DAC_sudo_require_authentication.cpp`
- `fic/CMakeLists.txt`
- `fic-gui/CMakeLists.txt`
- `fic-dick/CMakeLists.txt`
- `fic/src/core/main_function.h`
- `fic/src/core/main_function.cpp`
- `fic/src/modules/sysctl/Sysctl.cpp`
- `fic/src/modules/oss/submodules/DisplayManager/backends/DisplayManagerBackend.cpp`
- `fic/src/scripts/config/DAC.conf`
- `fic/src/scripts/lang/ru.lang`
- `fic/src/scripts/lang/en.lang`
- `tests/CMakeLists.txt`
- `tests/file-handler/FileHandlerOptionsTests.cpp`
- `tests/sudoers/SudoersConfigurationTests.cpp`
- `fic/README.md`
- `docs/architecture-diagrams.md`
- `docs/HANDOFF.md`

## Проверки

Выполнено успешно:

```bash
cmake --build /tmp/fic2-sudo-build -j2
ctest --test-dir /tmp/fic2-sudo-build --output-on-failure
cmake -S . -B /tmp/fic2-sudo-warnings -DBUILD_TESTING=ON \
  -DCMAKE_CXX_FLAGS="-Wall -Wextra -Wpedantic"
cmake --build /tmp/fic2-sudo-warnings \
  --target file_handler_options_tests sudoers_configuration_tests fic -j2
git diff --check
```

Все три CTest-проверки прошли. В тесте `sudoers_configuration_tests` установленный
`/usr/sbin/visudo` запускался только для временного файла в `/tmp`.
Предупреждений из новых Sudo/AtomicFileWriter-файлов усиленная сборка не выдала;
оставшиеся предупреждения относятся к существующему коду вне задачи.

Локальные проверки выше не изменяли `/etc/sudoers*`.

Дополнительно commit `37649c2` проверен на машине `172.17.1.105` с Debian 13,
GCC 14.2, CMake 3.31.6, OpenSSL 3.5.6 и SQLite 3.46.1:

- успешно собраны все цели, включая `fic`, `fic-gui`, `fic-cli`, `fic-dick` и
  `fic-session-agent`;
- `device_control_static_checks` прошел через CTest;
- `sudoers_configuration_tests` и `file_handler_options_tests` прошли при
  прямом запуске из `/home/admsys`, поскольку `/tmp` смонтирован с `noexec`;
- тест Sudo использовал системный `/usr/sbin/visudo` на временных файлах;
- реальный `visudo -c` успешно проверил `/etc/sudoers` и
  `/etc/sudoers.d/README`;
- в реальной конфигурации найдено нарушение новой политики:
  `/etc/sudoers:50` содержит `%sudo ALL=(ALL:ALL) NOPASSWD: ALL`;
- затем production-бинарник `fic --oneshot` прогнан от root на реальном
  `/etc/sudoers` и `/etc/sudoers.d` по матрице из 20 сценариев: основной файл,
  прямые и directory include, legacy-директивы, порядок файлов, 351 тег в
  одной строке, идемпотентность, managed override и его метаданные, а также
  fail-closed для позднего override, многострочного/составного правила, symlink,
  цикла, небезопасных владельца/режима/каталога, неверного hash `visudo`,
  ошибочного синтаксиса, `%`-подстановки и неподключенного managed-каталога;
- все 20 ожидаемых сценариев прошли; отдельно воспроизведен дефект валидного
  правила `(ALL:ALL) CWD=/tmp NOPASSWD: ...`, впоследствии исправленный;
- перед runtime-тестами созданы root-only резервные копии и аварийный systemd
  timer. После тестов исходные `/etc/sudoers*` и `/opt/fic` восстановлены,
  содержимое и метаданные sudoers сверены с архивом, `visudo -c` прошел, timer
  отключен, временные исходники, build-каталоги, скрипты и архивы удалены.

Для полной сборки на машине были установлены `libssl-dev`, `libsqlite3-dev`,
`nlohmann-json3-dev` и `qtbase5-dev` с их зависимостями.

После исправлений дополнительно выполнено:

- полная локальная сборка и все три CTest-проверки;
- сборка `fic`, `fic-gui` и `fic-dick` из пути
  `/tmp/fic-source-test-case`, содержащего `test`;
- сборка production `fic` на `172.17.1.105` из пути, содержащего `test`;
- runtime-применение правила `(ALL:ALL) CWD=/tmp NOPASSWD: ...` на реальном
  sudoers: правило успешно заменено на `PASSWD`, конфигурация прошла `visudo`;
- runtime-проверка графового preflight: поддерживаемое правило в первом файле
  осталось без изменений, когда во втором файле находилось неподдерживаемое
  многострочное правило;
- исходные `/etc/sudoers*` снова восстановлены и сверены с архивом, `/opt/fic`
  восстановлен, аварийный timer отключен, временные артефакты удалены.

Дополнительная матрица многострочных и некорректных правил:

- локальные CTest-проверки расширены вариантами, где `NOPASSWD` находится до
  переноса или на следующей физической строке, многострочными
  `!authenticate`/`exempt_group`, безопасными многострочными `PASSWD` и
  quoted Defaults;
- production `fic --oneshot` на `172.17.1.105` прошел 15 из 15 сценариев:
  восемь многострочных и семь синтаксически некорректных;
- многострочные нарушения завершаются fail-closed, сохраняют контрольные суммы
  всех файлов и не мешают безопасным многострочным правилам проходить без
  изменений;
- проверены лишний `ALL` перед `NOPASSWD`, отсутствие `:`, незакрытый Runas,
  пустая команда, завершающая запятая, оборванный `\\` и ошибка в include-файле;
- во всех некорректных случаях исходный `visudo` отклонил граф до записи, другие
  включенные файлы также остались неизменными;
- после матрицы `/etc/sudoers*` сверены с резервным архивом, `/opt/fic`
  восстановлен, `visudo -c` прошел, timer и временные артефакты удалены.

## Что осталось и риски

- Перед production-применением администратор должен зарегистрировать hash
  фактического `visudo`; иначе политика безопасно завершится ошибкой.
- Подстановки `%` в include-путях намеренно не поддерживаются и приводят к
  отказу. Это исключает чтение не того графа, но ограничивает редкие конфигурации.
- Составные `Host_Spec` и нарушающие многострочные правила требуют ручного
  разбиения на однострочные записи. Полноценное редактирование таких конструкций
  потребует отдельного синтаксического слоя с отображением логических строк на
  физические.
- Политика анализирует только локальный активный include-граф. Timestamp-кэш,
  PAM и внешние LDAP/SSSD-источники находятся вне ее заявленной семантики.
- Для администраторских файлов `/etc/sysctl.conf` и display manager сохранена
  совместимость с символическими ссылками. Их canonical target определяется во
  время записи; строгая фиксация target между чтением и записью пока не
  реализована. Для sudoers и FIC-owned хранилища hash symlink запрещен.
