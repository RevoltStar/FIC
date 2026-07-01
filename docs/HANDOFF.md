# FIC 2.0: передача контекста

Этот файл хранит текущее состояние работы между чатами. Он не является журналом
всей разработки и не заменяет `AGENTS.md` или архитектурную документацию.
Следующий агент должен сначала прочитать этот файл, затем проверить фактическое
состояние через `git status`.

## Текущий снимок

- Обновлено: 2026-06-30.
- Ветка: `main`.
- Базовый commit: `50ea3e2`.
- Текущая задача: добавить политики контроля безопасных параметров
  монтирования в `/etc/fstab` как подмодуль `Fstab` модуля `OSS`.

## Сделано

- Добавлен подмодуль `OSS/Fstab`:
  - базовый класс `Fstab` читает `/etc/fstab`, разбирает активные строки на
    поля fstab и исправляет четвертое поле `options`;
  - правки сохраняются через существующий `FileHandler::saveFile()` с
    временным файлом, `fsync` и `rename`;
  - runtime `mount`/`remount` не выполняется;
  - для политик с явно заданными точками монтирования отсутствие подходящей
    записи в `/etc/fstab` считается ошибкой применения.
- Реализованы политики:
  - `fstab_tmp_secure_options`: для `/tmp` требует `nodev,nosuid,noexec`;
  - `fstab_var_tmp_secure_options`: для `/var/tmp` требует
    `nodev,nosuid,noexec`;
  - `fstab_dev_shm_secure_options`: для `/dev/shm` требует
    `nodev,nosuid,noexec`;
  - `fstab_home_secure_options`: для `/home` требует `nodev,nosuid`;
  - `fstab_removable_media_secure_options`: для `/media`, `/mnt`,
    `/run/media` требует `nodev,nosuid,noexec`;
  - `fstab_world_writable_mounts_secure_options`: для записей fstab, чьи точки
    монтирования существуют как world-writable каталоги, требует
    `nodev,nosuid,noexec`;
  - `fstab_no_insecure_options`: для типовых чувствительных точек заменяет
    конфликтующие `dev,suid,exec` на `nodev,nosuid,noexec`.
- Политики зарегистрированы в `init_policyMap()`.
- Добавлены значения по умолчанию в `OSS.conf`.
- Добавлены русская и английская локализации.
- Обновлена карта модулей в `docs/architecture-diagrams.md`.

## Измененные файлы

- `fic/src/modules/oss/submodules/Fstab.h`
- `fic/src/modules/oss/submodules/Fstab.cpp`
- `fic/src/modules/oss/submodules/Fstab/OSS_fstab_tmp_secure_options.*`
- `fic/src/modules/oss/submodules/Fstab/OSS_fstab_var_tmp_secure_options.*`
- `fic/src/modules/oss/submodules/Fstab/OSS_fstab_dev_shm_secure_options.*`
- `fic/src/modules/oss/submodules/Fstab/OSS_fstab_home_secure_options.*`
- `fic/src/modules/oss/submodules/Fstab/OSS_fstab_removable_media_secure_options.*`
- `fic/src/modules/oss/submodules/Fstab/OSS_fstab_world_writable_mounts_secure_options.*`
- `fic/src/modules/oss/submodules/Fstab/OSS_fstab_no_insecure_options.*`
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
git diff --check
cmake -S . -B /tmp/fic-build-check
cmake --build /tmp/fic-build-check --target fic -j2
cmake --build /tmp/fic-build-check --target fic -j2  # повторно после изменения поведения missing mount point
```

Результат: цель `fic` успешно собрана. `cmake -S` вывел только существующие
предупреждения о deprecated `cmake_minimum_required` в CMakeLists.

Не выполнялось:

- применение новых fstab-политик;
- запись в `/etc/fstab`;
- `mount`, `remount`, udev trigger/retrigger;
- сборка `fic-gui`, `fic-cli`, `fic-dick`;
- сборка deb/rpm пакетов.

## Решения и риски

- Если целевая точка монтирования явно заданной fstab-политики отсутствует в
  `/etc/fstab`, политика ничего не добавляет и возвращает ошибку применения.
- Строки fstab после исправления форматируются табами между полями; inline-
  комментарии сохраняются как дополнительные поля, но исходное выравнивание
  активной строки может измениться.
- Уже смонтированные файловые системы не меняются до явного remount или
  перезагрузки. Это сделано намеренно, чтобы обычная проверка политики не
  изменяла runtime-состояние хоста.
- Политика для `/home` не включает `noexec`, чтобы не ломать пользовательские
  сценарии запуска программ из домашнего каталога.
