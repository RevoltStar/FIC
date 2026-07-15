# FIC 2.0: передача контекста

Этот файл хранит текущее состояние работы между чатами. Он не является журналом
всей разработки и не заменяет `AGENTS.md` или архитектурную документацию.

## Текущий снимок

- Обновлено: 2026-07-15.
- Ветка: `main`.
- Базовый commit: `eea7a04`.
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
  пока обрабатываются fail-closed: FIC сообщает источник и не переписывает
  неоднозначную конструкцию.
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
  symlink-защиты, сложных fail-closed случаев и реального `visudo` на временном
  файле. Отдельный набор проверяет создание, запрет создания, metadata policy,
  symlink и удаление между load/save для `FileHandler`.
- Обновлены конфигурация политики, русская/английская локализация, README и
  архитектурная схема.

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

Реальное применение политики и запись в `/etc/sudoers*` не выполнялись.

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
- При ошибке в одном из нескольких файлов уже успешно ужесточенные предыдущие
  файлы не откатываются: права не расширяются, но операция может быть частичной
  и вернет ошибку с диагностикой.
- Для администраторских файлов `/etc/sysctl.conf` и display manager сохранена
  совместимость с символическими ссылками. Их canonical target определяется во
  время записи; строгая фиксация target между чтением и записью пока не
  реализована. Для sudoers и FIC-owned хранилища hash symlink запрещен.
