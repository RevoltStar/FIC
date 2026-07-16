# FIC 2.0: передача контекста

Этот файл хранит текущее состояние работы между чатами. Он не является журналом
всей разработки и не заменяет `AGENTS.md` или документацию компонентов.

## Текущий снимок

- Обновлено: 2026-07-16.
- Ветка: `main`.
- Базовый commit: `d3ec70e`.
- Текущая задача: поддержка полного набора постоянных конфигураций procps-ng
  `sysctl --system` в политиках модуля `SYSCTL`.

## Сделано

- Добавлен доменный обработчик `SysctlConfiguration`. Общий
  `ConfigFileHandler` намеренно не расширялся: его однофайловая модель не может
  выразить приоритеты и глобальный порядок sysctl.
- Обрабатываются фиксированные каталоги `/etc/sysctl.d`, `/run/sysctl.d`,
  `/usr/local/lib/sysctl.d`, `/usr/lib/sysctl.d`, `/lib/sysctl.d`, после них —
  `/etc/sysctl.conf`.
- Для одинаковых имен выбирается файл из первого каталога в порядке приоритета;
  выбранные `*.conf` сортируются глобально по имени. Файлы с другими суффиксами
  и подавленные одноименные файлы не разбираются.
- Поддержаны комментарии `#`/`;`, повторные параметры, `-key = value`, ключи с
  точками или slash-нотацией, glob-назначения, исключения `-key` без `=` и
  symlink-mask на `/dev/null`. Явное назначение ключа исключает его из glob-
  совпадений.
- Нарушение определяется по последнему эффективному значению точного ключа.
  Затененные более ранние строки не переписываются и сами по себе не считаются
  нарушением.
- Исправление записывается только в управляемый блок в конце
  `/etc/sysctl.conf`. Значения других политик в блоке сохраняются, ключи
  выводятся детерминированно, повторное применение идемпотентно.
- Перед записью повторно сверяется снимок всех активных файлов. Запись идет
  через `AtomicFileWriter`, production-файл получает `root:root 0644`. После
  записи граф перечитывается и проверяется постусловие; при ошибке исходный
  `/etc/sysctl.conf` восстанавливается либо созданный файл удаляется с `fsync`
  каталога.
- Активные файлы и их canonical target должны принадлежать root, не быть
  доступны на запись группе/остальным и находиться в безопасном каталоге.
  Маска `/dev/null` разрешена отдельно.
- `Sysctl::apply()` защищен общим mutex, использует новый обработчик, сообщает
  источник эффективного значения и отдельно читает соответствующий
  `/proc/sys`. Несовпадение runtime журналируется, но работающий kernel runtime
  не изменяется.
- Добавлен CTest-набор из 13 сценариев: глобальный порядок, приоритет одинаковых
  имен, игнорирование подавленного некорректного файла, последний
  `/etc/sysctl.conf`, slash-нотация, glob с исключением, явное значение против
  glob, `/dev/null` mask, отсутствие лишней записи, несколько managed-значений,
  перенос блока в конец, malformed-блок и некорректная активная строка.
- Тестовый бинарник получил ручные режимы `--inspect KEY` и
  `--ensure KEY VALUE`; они не входят в production-бинарник.
- Добавлен root-only integration-скрипт с автоматическим backup/restore
  реальных `/etc/sysctl*`.
- Обновлены README демона и архитектурная схема.

## Измененные файлы

- `fic/src/modules/sysctl/Sysctl.h`
- `fic/src/modules/sysctl/Sysctl.cpp`
- `fic/src/modules/sysctl/SysctlConfiguration.h`
- `fic/src/modules/sysctl/SysctlConfiguration.cpp`
- `tests/sysctl/SysctlConfigurationTests.cpp`
- `tests/sysctl/RemoteSysctlIntegration.sh`
- `tests/CMakeLists.txt`
- `fic/README.md`
- `docs/architecture-diagrams.md`
- `docs/HANDOFF.md`

## Проверки

Выполнено успешно:

```bash
cmake -S . -B /tmp/fic2-sysctl-build -DBUILD_TESTING=ON
cmake --build /tmp/fic2-sysctl-build \
  --target sudoers_configuration_tests file_handler_options_tests \
           sysctl_configuration_tests fic -j2
ctest --test-dir /tmp/fic2-sysctl-build --output-on-failure

cmake -S . -B /tmp/fic2-sysctl-warnings -DBUILD_TESTING=ON \
  -DCMAKE_CXX_FLAGS="-Wall -Wextra -Wpedantic"
cmake --build /tmp/fic2-sysctl-warnings \
  --target sysctl_configuration_tests fic -j2
git diff --check
```

Все четыре CTest-проверки прошли. Новые файлы Sysctl собрались без
предупреждений; warnings-сборка показывает только существующие предупреждения в
других файлах проекта.

Тесты работали с временными деревьями в `/tmp`. Реальные `/etc/sysctl*` и
`/proc/sys` не изменялись, `sysctl --system` не запускался.

Дополнительно изменения проверены на `172.17.1.105` (Debian 13.5, GCC 14.2,
CMake 3.31.6, procps-ng 4.0.4):

- успешно собраны `fic` и три C++ test target;
- все 13 сценариев `sysctl_configuration_tests` прошли;
- production-read первоначально обнаружил дефект на строках Debian вида
  `-net.ipv4.conf.all.rp_filter`; после добавления glob/exclusion-семантики
  значения обработчика совпали с `/usr/sbin/sysctl --dry-run --system`;
- на реальных `/etc/sysctl.d`, `/run/sysctl.d` и `/etc/sysctl.conf` прошли
  глобальный порядок, приоритет одинакового basename, `/dev/null` mask,
  отсутствие записи при правильном значении, managed override, `root:root 0644`,
  procps dry-run, идемпотентность, несколько managed-ключей, fail-closed для
  malformed-блока и world-writable активного файла;
- integration-скрипт восстановил исходный `/etc/sysctl.conf` размером 275 байт
  и метаданные `root:root 0644`, удалил тестовые файлы и созданный
  `/run/sysctl.d`; managed-маркеров после теста нет;
- применялись только dry-run и чтение `/proc/sys`, kernel runtime не менялся;
- удалены удаленные исходники, build-каталог и случайный pager-артефакт.

Общий CTest на машине прошел 3 из 4 наборов. Единственный сбой находится в
старом `sudoers_configuration_tests`: сценарий
`invalid included rule must fail before changing other files`. Sysctl-набор,
FileHandler и static checks прошли; это отдельный Sudo/visudo-сигнал и не
вызван связями с новым Sysctl-кодом.

## Что осталось и риски

- Реализация сознательно моделирует procps-ng `sysctl --system`. Нативный
  `systemd-sysctl` не читает `/etc/sysctl.conf`; на системах без ссылки вроде
  `/etc/sysctl.d/99-sysctl.conf -> ../sysctl.conf` managed-блок не будет
  применен при загрузке. Поддержка такого профиля требует отдельного
  согласованного managed-файла в `/etc/sysctl.d` и выбора loader profile.
- Runtime ядра пока только проверяется. Для автоматического изменения нужен
  отдельный безопасный контракт через `VerifiedProcessExecutor`, hash
  фактического `sysctl`, проверка результата в `/proc/sys` и определенная
  стратегия отката disk/runtime.
- Парсер вычисляет точные ключи текущих политик FIC с учетом glob и исключений,
  но не разворачивает glob в полный перечень существующих `/proc/sys` узлов.
- Совместимость `/etc/sysctl.conf` с символическими ссылками сохранена.
  `AtomicFileWriter` разрешает canonical target перед записью; полноценной
  фиксации inode между чтением и rename нет, как и у прежней реализации.
