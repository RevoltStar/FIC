# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-07-29.
- Ветка: `main`.
- Базовый commit: `a73c184`.
- Текущая задача: compile-time профили целевых дистрибутивов, включая
  дистрибутиво-зависимые данные политик, и отдельные пакетные наборы Debian 12,
  Ubuntu 24.04 и ALT p11.
- Реализация завершена, проверена и зафиксирована текущим коммитом.

## Сделано

- Добавлен обязательный CMake-параметр `FIC_TARGET_PLATFORM`. Поддерживаются
  только `debian-12`, `ubuntu-24.04` и `alt-p11`; неизвестное или отсутствующее
  значение останавливает конфигурацию CMake.
- CMake выбирает ровно один distribution-specific source, реализующий
  `makeBuildPlatformProfile()`. Профили собраны во внутреннюю библиотеку
  `fic-platform`.
- Профиль содержит host compatibility и независимые секции `systemTools`,
  `ssh`, `sudo`, `displayManager` и `dac`. В них находятся кандидаты
  `systemctl`/`loginctl`, SSH layout и units, sudoers/`visudo`, конфиги display
  manager и наборы файлов/команд для DAC.
- ALT p11 использует `/etc/openssh/sshd_config`, `/usr/sbin/sshd` и
  `sshd.service`; Debian 12 и Ubuntu 24.04 используют
  `/etc/ssh/sshd_config`.
- `Ssh` больше не содержит static production path и общий mutable
  `SshConfigFileHandler`. Все четыре SSH-политики получают копию одного
  профиля через `init_policyMap(platform)`, а `SshRuntime` использует SSH-
  секцию вместе с общей `systemTools` для `sshd -T`, include-аудита и reload.
- Удалена неиспользуемая shadow-карта `expected` из
  `DAC_blocking_user_access_to_system_files.h`, в которой оставалась отдельная
  литеральная копия SSH-пути.
- `systemctl` и `loginctl` больше не выбираются локальными fallback-списками:
  профиль передается в SSH runtime, display-manager policies, перечисление
  графических сессий и IPC-команду `lock`.
- Все sudo-политики получают из профиля основной `/etc/sudoers`, managed-файл
  и кандидаты `visudo`; production defaults удалены из
  `SudoersConfigurationOptions`.
- Пути SDDM, LightDM и упорядоченные кандидаты GDM перенесены из backend-классов
  в профиль. Выбор существующего GDM-файла выполняется только внутри набора
  кандидатов уже выбранного compile-time профиля.
- Списки `blocking_user_access_to_system_files` и `systemcommandlock` перенесены
  в DAC-секцию профиля. Debian/Ubuntu используют `/etc/bash.bashrc`,
  `/boot/grub/grub.cfg` и `/usr/sbin/ip`; ALT p11 использует `/etc/bashrc`,
  `/etc/grub.cfg`, `/etc/securetty` и `/sbin/ip`. Удалены неподтвержденные
  универсальные `/etc/ntpd.conf` и `/etc/sysconfig/securetty`.
- GUI/CLI получают точный DAC-список выбранного профиля через restriction
  политики; из локализаций удален устаревший универсальный список.
- Daemon валидирует compile-time профиль и `/etc/os-release` до инициализации
  runtime paths, сокета и политик. Профиль не выбирается автоматически:
  несовместимый пакет завершается fail-closed. `fic --version` показывает
  target profile.
- Debian 12 и ALT p11 packaging явно передают свои профили в CMake.
- Добавлен отдельный Ubuntu 24.04 `.deb` entry point, Dockerfile и Docker
  wrapper. Он создает собственный набор пакетов с тегом `ubuntu2404` и
  профилем `ubuntu-24.04`.
- Добавлены C++ и static tests профилей, проверки fail-closed совместимости,
  абсолютных путей, полноты всех секций, корректности DAC-правил, отсутствия
  platform hardcode в consumer-коде, выбора package profile и парсинга
  `os-release`.
- Обновлены `README.md`, `fic/README.md`, packaging README,
  `docs/architecture-diagrams.md` и инструкции сборки в `AGENTS.md`.

## Локальные проверки

Успешно выполнены:

```bash
git diff --check

cmake -S . -B /tmp/fic-build-alt \
  -DFIC_TARGET_PLATFORM=alt-p11 -DBUILD_TESTING=ON
cmake --build /tmp/fic-build-alt -j2
ctest --test-dir /tmp/fic-build-alt --output-on-failure
```

Полностью собраны `fic`, `fic-cli`, `fic-gui`, `fic-dick`,
`fic-session-agent` и общие библиотеки. Из 12 CTest-проверок 11 прошли,
`admin_socket_tests` штатно пропущен с configured `SKIP_RETURN_CODE=77`;
ошибок нет.

Отдельно полностью собран daemon и выполнен `platform_profile_tests` для:

```text
debian-12
ubuntu-24.04
alt-p11
```

Профильные тесты и static checks прошли для всех трех сборок. Конфигурация без
`FIC_TARGET_PLATFORM` проверена отдельно и ожидаемо завершилась CMake-ошибкой.

Debian 12 и Ubuntu 24.04 daemon-бинарники запущены на ALT-хосте только до
platform guard: оба вернули код 1 с диагностикой несовместимого `ID=altlinux`,
до runtime paths, сокета и применения политик. ALT-бинарник успешно вывел:

```text
fic 2.0 target-platform=alt-p11
```

Также успешно выполнен `bash -n` для затронутых Debian, Ubuntu и ALT packaging-
скриптов. Реальные `.deb`/`.rpm` пакеты не собирались: тяжелые Docker package
builds не запускались.

## Что осталось

- Перед выпуском пакетов выполнить штатные Docker package builds для нужных
  дистрибутивов.
- Runtime-команды конкретных desktop environment, `/run/user`, `/etc/fstab`,
  `/proc/sys` и стандартные каталоги sysctl намеренно не помещены в профиль:
  это capability-, XDG-, FHS- или kernel-зависимые данные.
- Shell helpers `fic-notify-dispatcher` и `fic-udevadm-trigger` пока разрешают
  команды через штатный `PATH`/набор executable-кандидатов. Если их потребуется
  сделать строго target-specific, нужен единый build-time источник данных и
  для C++, и для генерируемых scripts; не дублировать значения локальными
  `#ifdef` или несвязанными defaults.
