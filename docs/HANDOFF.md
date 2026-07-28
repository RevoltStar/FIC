# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-07-28.
- Ветка: `main`.
- Базовый commit: `452473c`.
- Текущая задача: рефакторинг SSH-разбора и устранение расхождений с
  синтаксисом и `Include`/`Match`-контекстом OpenSSH.

## Сделано

- Выделен общий `SshConfigSyntax`, который разбирает ключ, аргументы, варианты
  разделителя пробел/`=`, двойные кавычки ключа, кавычки аргументов, escape и
  inline-комментарии.
- `SshConfigFileHandler` вынесен из `Ssh.cpp` в отдельный
  `SshConfigFile.{h,cpp}` и переведен на общий синтаксический разбор.
- Редактор основного файла больше не комментирует повторяющиеся посторонние
  директивы при изменении одной политики. Дубликаты самого изменяемого
  параметра по-прежнему устраняются в глобальной части файла.
- Read-only обход `Include`/`Match` вынесен из `SshRuntime.cpp` в
  `SshConfigAudit.{h,cpp}`. `SshRuntime` оставлен координатором effective-
  проверки, policy-specific сравнения и runtime activation.
- Контекст `Match` передается во включенный файл копированием. Изменение
  контекста внутри include больше не протекает в содержащий файл или следующий
  результат glob, что соответствует поведению OpenSSH.
- Условные `Match`, контролируемые значения и `Include` в допустимой форме
  `Keyword=Value` больше не обходят аудит. Двойные кавычки вокруг ключевого
  слова также распознаются.
- Include-пути, начинающиеся с `~`, намеренно завершают аудит fail-closed:
  переносимое и однозначное соответствие их раскрытия разными реализациями
  `glob` не предполагается.
- Добавлены регрессионные тесты общего синтаксиса, редактора файла, сохранения
  повторных `Include`, `Match=`/`Include=`, условных значений через `=` и
  изоляции `Match` между файлами.
- Обновлены `fic/README.md` и `docs/architecture-diagrams.md`.

## Основные измененные зоны

- `fic/src/modules/net/submodules/Ssh.cpp`, `Ssh.h`.
- `fic/src/modules/net/submodules/SshConfigSyntax.*`.
- `fic/src/modules/net/submodules/SshConfigFile.*`.
- `fic/src/modules/net/submodules/SshConfigAudit.*`.
- `fic/src/modules/net/submodules/SshRuntime.cpp`.
- `tests/CMakeLists.txt`, `tests/ssh/SshRuntimeTests.cpp`.
- `fic/README.md`, `docs/architecture-diagrams.md`.

## Проверки

Успешно выполнены:

```bash
cmake -S . -B /tmp/fic2-ssh-refactor -DBUILD_TESTING=ON
cmake --build /tmp/fic2-ssh-refactor --target ssh_runtime_tests fic -j2
ctest --test-dir /tmp/fic2-ssh-refactor --output-on-failure \
  -R '^ssh_runtime_tests$'
cmake --build /tmp/fic2-ssh-refactor -j2
ctest --test-dir /tmp/fic2-ssh-refactor --output-on-failure
cmake -S . -B /tmp/fic2-ssh-refactor-sanitized -DBUILD_TESTING=ON \
  -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Wpedantic'
cmake --build /tmp/fic2-ssh-refactor-sanitized \
  --target ssh_runtime_tests -j2
ASAN_OPTIONS=detect_leaks=0 \
  /tmp/fic2-ssh-refactor-sanitized/tests/ssh_runtime_tests
git diff --check
```

Полная сборка и все девять CTest-сценариев завершились успешно;
`admin_socket_tests` штатно пропущен по коду 77. SSH-тесты прошли также с
ASan/UBSan. Предупреждения `-Wall/-Wextra` относятся к существующим
неиспользуемым параметрам и переменной в `fic-core`, а не к измененным
SSH-файлам.

Реальные SSH reload, изменение `/etc/ssh/sshd_config`, policy apply и запись в
`/opt/fic` не выполнялись. `sshd` в текущем окружении отсутствует, поэтому
дифференциальная проверка на реальном OpenSSH не запускалась.

## Что осталось и риски

- Нужен integration-тест с реальным `sshd -T -f` в одноразовом контейнере или
  VM для вариантов пробел/`=`, кавычек, glob-include и вложенных `Match`.
- Перед реальным применением SSH-политик нужны hashes выбранных `sshd` и
  `systemctl`, обычно `/usr/sbin/sshd` и `/usr/bin/systemctl`.
- Runtime SSH по-прежнему рассчитан на `ssh.service`/`sshd.service` под
  systemd. Отдельно запущенный daemon и socket activation не определяются.
- Структурированный результат по стадиям проверки и декларативная таблица
  policy-specific сравнений в эту итерацию намеренно не включены: они не нужны
  для исправления ложного успеха и потребуют отдельного изменения API.
