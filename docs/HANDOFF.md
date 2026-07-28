# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-07-28.
- Ветка: `main`.
- Базовый commit: `c0d3081`.
- Текущая задача: устранение ложного успеха SSH-политик при нескольких
  effective-значениях, `ListenAddress` и условных `Match`/`Include`.

## Сделано

- `SshRuntime::effectiveValue()` заменен на множественный
  `effectiveValues()`. Поиск по репозиторию подтвердил, что старый API
  использовался только общей реализацией SSH-политик и SSH-тестом; другие
  политики от него не зависели.
- Добавлен единый `verifyPolicyValue()`, который один раз получает полный вывод
  проверяемого `sshd -T`. Скалярные параметры требуют ровно одно ожидаемое
  значение.
- Политика `ssh_port` требует единственный effective-порт и отдельно проверяет
  явно заданные порты effective-`ListenAddress`. Дополнительный порт приводит к
  `Failed`, поэтому политика больше не может подтвердить конфигурацию, в
  которой sshd продолжает слушать другой порт.
- Добавлен рекурсивный read-only аудит основного `sshd_config` и полного графа
  `Include`: поддерживаются glob, лексический порядок, вложенные и условные
  include; циклы, глубина более 16 и граф более 256 файлов обрабатываются
  fail-closed.
- Условные значения контролируемого параметра внутри `Match` проверяются
  отдельно, потому что обычный `sshd -T` без `-C` их не раскрывает.
  Эквивалентные и доказуемо более строгие значения разрешены. Для
  `PermitRootLogin` используется порядок `no`, `forced-commands-only`,
  `prohibit-password`, `yes`; для `MaxAuthTries` меньшее положительное число
  считается более строгим. Остальные параметры требуют точного совпадения.
- `Ssh::apply()` переведен на новую комплексную проверку. Существующий
  атомарный откат до reload сохраняется при любой ошибке effective-значений или
  аудита источников.
- SSH-тесты расширены сценариями нескольких портов, конфликтующего
  `ListenAddress`, слабого и более строгого `Match`, прямого и вложенного
  `Include`, цикла include и нескольких effective-значений скалярного
  параметра.
- Обновлены `fic/README.md` и `docs/architecture-diagrams.md`.

## Основные измененные зоны

- `fic/src/modules/net/submodules/Ssh*`.
- `tests/ssh/SshRuntimeTests.cpp`.
- `fic/README.md`, `docs/architecture-diagrams.md`.

## Проверки

Успешно выполнены:

```bash
cmake --build /tmp/fic2-last-commit-review -j2
/tmp/fic2-last-commit-review/tests/ipc_paths_tests
/tmp/fic2-last-commit-review/tests/sudoers_configuration_tests
/tmp/fic2-last-commit-review/tests/file_handler_options_tests
/tmp/fic2-last-commit-review/tests/sysctl_configuration_tests
/tmp/fic2-last-commit-review/tests/ssh_runtime_tests
/tmp/fic2-last-commit-review/tests/runtime_paths_tests
cmake -S . -B /tmp/fic2-ssh-sanitized -DBUILD_TESTING=ON \
  -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Wpedantic'
cmake --build /tmp/fic2-ssh-sanitized --target ssh_runtime_tests -j2
ASAN_OPTIONS=detect_leaks=0 /tmp/fic2-ssh-sanitized/tests/ssh_runtime_tests
git diff --check
rg -n "effectiveValue\\(" . --glob '!build*' --glob '!dist/**'
```

Собраны все цели, шесть перечисленных тестовых бинарников завершились с кодом
0. SSH-тесты также прошли с ASan/UBSan; LeakSanitizer отключен, потому что он не
работает под действующим ptrace/sandbox. Сообщения об ожидаемых отказах файловых
операций внутри негативных тестов не являются ошибками тестового запуска.
`ctest` в текущем окружении отсутствует, поэтому бинарники запускались напрямую.
`admin_socket_tests` собран, но завершился кодом 77: sandbox запрещает
`bind(AF_UNIX)`.

Реальные SSH reload, изменение `sshd_config`, policy apply, записи в
`/proc/sys` и `/opt/fic`, remount, device mutation и установка пакетов не
выполнялись. Docker-сборки deb/rpm не запускались.

## Что осталось и риски

- Перед реальным применением SSH-политик администратор должен сохранить hashes
  выбранных `sshd` и `systemctl`, обычно `/usr/sbin/sshd` и
  `/usr/bin/systemctl`. Без них политика корректно завершится ошибкой.
- Runtime SSH рассчитан на поддерживаемые systemd-дистрибутивы. Отдельный
  `sshd`, запущенный вне `ssh.service`/`sshd.service`, автоматически не
  перезагружается.
- Нужен SSH runtime smoke в одноразовой VM: реальные `sshd -T` и reload с
  установленными hashes, несколько `Port`, порт в `ListenAddress`, условный
  `Match` и include из стандартного каталога дистрибутива.
- Аудит намеренно fail-closed для неизвестных условных параметров: только
  `PermitRootLogin` и `MaxAuthTries` имеют формализованный порядок строгости.
  При регистрации новой SSH-политики нужно решить, допускает ли ее значение
  безопасный частичный порядок, либо оставить точное совпадение.
- Перед merge желательно запустить `admin_socket_tests` вне sandbox и тяжелые
  Debian 12/ALT p11 package builds.
