# FIC 2.0: передача контекста

Этот файл хранит текущее состояние работы между чатами. Он не является журналом
всей разработки и не заменяет `AGENTS.md` или архитектурную документацию.
Следующий агент должен сначала прочитать этот файл, затем проверить фактическое
состояние через `git status`.

## Текущий снимок

- Обновлено: 2026-07-01.
- Ветка: `main`.
- Базовый commit: `afc6ff5`.
- Текущая задача: перевести политики контроля `/etc/fstab` на профильную модель
  без дублирующихся уровней и ограничить набор политик безопасным ядром.

## Сделано

- Подмодуль `OSS/Fstab` теперь поддерживает:
  - фиксированный набор mount options для политик без осмысленного выбора;
  - профильный набор options для политик, где `minimal`, `optimal` или `strict`
    действительно отличаются по fstab-enforceable поведению;
  - удаление конфликтующих опций `dev/nodev`, `suid/nosuid`, `exec/noexec`,
    `rw/ro`, а также замену key-value options с тем же ключом, например
    `umask=...` или `mode=...`;
  - ошибку применения, если для явно заданной точки монтирования нет активной
    записи в `/etc/fstab`;
  - fallback к default profile, если значение профильной политики отсутствует
    в установленном `OSS.conf`; если значение задано, но невалидно, применение
    завершается ошибкой;
  - атомарное сохранение через существующий `FileHandler::saveFile()`.
- Реализовано безопасное ядро fstab-политик:
  - `fstab_tmp_profile`: `optimal` = `rw,nodev,nosuid,noexec,relatime`,
    `minimal` = `rw,nodev,nosuid,relatime`;
  - `fstab_var_tmp_profile`: `optimal` = `rw,nodev,nosuid,noexec,relatime`,
    `minimal` = `rw,nodev,nosuid,relatime`;
  - `fstab_dev_shm_profile`: `optimal` =
    `rw,nodev,nosuid,noexec,mode=1777`, `minimal` =
    `rw,nodev,nosuid,mode=1777`;
  - `fstab_home_profile`: `optimal` = `rw,nodev,nosuid,relatime`,
    `strict` = `rw,nodev,nosuid,noexec,relatime`;
  - `fstab_removable_media_profile`: `optimal` = `nodev,nosuid,noexec`,
    `strict` = `ro,nodev,nosuid,noexec`;
  - `fstab_var_log_secure_options`: fixed
    `rw,nodev,nosuid,noexec,relatime`;
  - `fstab_var_log_audit_secure_options`: fixed
    `rw,nodev,nosuid,noexec,relatime`;
  - `fstab_boot_profile`: `minimal` = `nodev,nosuid,noexec`,
    `optimal` = `ro,nodev,nosuid,noexec`;
  - `fstab_boot_efi_profile`: `minimal` =
    `nodev,nosuid,noexec,umask=0077`, `optimal` =
    `ro,nodev,nosuid,noexec,umask=0077`;
  - `fstab_srv_profile`: `minimal` = `nodev,nosuid`,
    `optimal` = `nodev,nosuid,noexec`;
  - `fstab_opt_profile`: fixed `nodev`.
- Удалены generic-политики `fstab_world_writable_mounts_secure_options` и
  `fstab_no_insecure_options`, чтобы не дублировать безопасное ядро.
- Обновлены регистрация политик, `OSS.conf`, русская и английская локализации,
  а также `docs/architecture-diagrams.md`.

## Измененные файлы

- `fic/src/modules/oss/submodules/Fstab.h`
- `fic/src/modules/oss/submodules/Fstab.cpp`
- `fic/src/modules/oss/submodules/Fstab/OSS_fstab_*`
- `fic/src/core/main_function.h`
- `fic/src/core/main_function.cpp`
- `fic/src/scripts/config/OSS.conf`
- `fic/src/scripts/lang/ru.lang`
- `fic/src/scripts/lang/en.lang`
- `docs/architecture-diagrams.md`
- `docs/HANDOFF.md`

## Проверки

Выполнено:

```bash
cmake -S . -B /tmp/fic-build-check
cmake --build /tmp/fic-build-check --target fic -j2
cmake --build /tmp/fic-build-check --target fic -j2  # повторно после fallback для отсутствующего profile value
```

Результат: цель `fic` успешно собрана. `cmake -S` вывел только существующие
предупреждения о deprecated `cmake_minimum_required` в CMakeLists.

Не выполнялось:

- применение fstab-политик;
- запись в `/etc/fstab`;
- `mount`, `remount`, udev trigger/retrigger;
- сборка `fic-gui`, `fic-cli`, `fic-dick`;
- сборка deb/rpm пакетов.

## Решения и риски

- Политики предлагают только уровни, которые меняют fstab options. Если
  строгий профиль из исходной матрицы требовал только quota, private namespace,
  очистку или мониторинг, отдельный `strict` здесь не добавлялся.
- Уже смонтированные файловые системы не меняются до явного remount или
  перезагрузки. Это сделано намеренно, чтобы обычная проверка политики не
  изменяла runtime-состояние хоста.
- `mode=1777` применяется только политикой `/dev/shm`, где ожидается tmpfs.
  Для `/tmp` и `/var/tmp` права 1777 из матрицы пока не применяются как fstab
  option, чтобы не добавить tmpfs-специфичную опцию к обычной дисковой ФС.
- Политики для `/boot` и `/boot/efi` имеют `ro` только в `optimal`, потому что
  read-only режим может мешать обновлениям.
- Для `/opt` не применяется `ro`: в этом проекте `/opt/fic` содержит runtime-
  данные FIC (`config`, `log`, `db`, `notify`, `lockstatus`), и read-only mount
  всего `/opt` ломает работу демона и сборщика устройств.
