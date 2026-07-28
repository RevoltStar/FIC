# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-07-28.
- Ветка: `main`.
- Базовый commit: `65285c7`.
- Текущая задача: завершение и подключение политики `ssh_pubkey_auth`.
- Задача завершена в рабочем дереве, изменения не закоммичены.

## Сделано

- `NET_ssh_pubkey_auth` зарегистрирована в `init_policyMap()`.
- В seed `NET.conf` добавлена отключенная по умолчанию политика с фиксированным
  значением `yes`; добавлены русское и английское отображение.
- `FixedPolicyTypeValue` получил обратно совместимый конструктор с конкретным
  встроенным значением. Для `ssh_pubkey_auth` это запрещает запись через IPC
  значений `no`, `ENABLE` и произвольных строк, сохраняя read-only editor.
- Встроенное фиксированное значение используется при отсутствии `.value` в
  старом `NET.conf`. Это поддерживает обновление Debian conffile и RPM
  `%config(noreplace)` без перезаписи пользовательского файла.
- `policy_value` теперь возвращает доступное встроенное значение, даже если
  отдельной строки в конфигурации еще нет.
- Аудит условных SSH-переопределений теперь явно называет контролируемый
  параметр в диагностике.
- Добавлены тесты фиксированного значения, upgrade-сценария без `.value` и
  fail-closed обработки `Match ... PubkeyAuthentication no`.
- Добавлен статический CTest, проверяющий регистрацию политики, seed-конфиг и
  обе локализации.
- Обновлены описание SSH в `fic/README.md` и карта политик в
  `docs/architecture-diagrams.md`.

## Основные измененные зоны

- `fic/src/core/main_function.cpp`, `fic/src/main.cpp`.
- `fic/src/modules/net/submodules/ssh/NET_ssh_pubkey_auth.cpp`.
- `fic/src/modules/net/submodules/SshRuntime.cpp`.
- `fic-common/fic-policy/include/fic/policy/{Policy,PolicyTypeValue}.h`.
- `fic-common/fic-policy/src/PolicyTypeValue.cpp`.
- `fic/src/scripts/config/NET.conf`.
- `fic/src/scripts/lang/{ru,en}.lang`.
- `tests/CMakeLists.txt`, `tests/ssh/SshRuntimeTests.cpp`,
  `tests/ssh/static_checks.py`.
- `fic/README.md`, `docs/architecture-diagrams.md`.

## Проверки

Успешно выполнены:

```bash
cmake -S . -B /tmp/fic2-ssh-pubkey -DBUILD_TESTING=ON
cmake --build /tmp/fic2-ssh-pubkey \
  --target ssh_runtime_tests fic fic-gui fic-cli -j2
ctest --test-dir /tmp/fic2-ssh-pubkey --output-on-failure \
  -R '^(ssh_runtime_tests|ssh_policy_static_checks)$'
cmake --build /tmp/fic2-ssh-pubkey -j2
ctest --test-dir /tmp/fic2-ssh-pubkey --output-on-failure
git diff --check
```

Полная сборка завершилась успешно. Из десяти CTest-сценариев девять прошли,
`admin_socket_tests` штатно пропущен по коду 77.

Реальные SSH reload, изменение `/etc/ssh/sshd_config`, policy apply, установка
пакетов и запись в `/opt/fic` не выполнялись.

## Что осталось и риски

- Нужен integration-тест с реальным `sshd -T -f` в одноразовом контейнере или
  VM: `sshd` в текущем окружении отсутствует.
- Перед реальным применением нужны hashes выбранных `sshd` и `systemctl`,
  обычно `/usr/sbin/sshd` и `/usr/bin/systemctl`.
- Политика намеренно только включает аутентификацию по открытым ключам. Она не
  проверяет наличие `authorized_keys` и не отключает парольную или
  keyboard-interactive аутентификацию.
- В старой установке отсутствующий `ssh_pubkey_auth.status` трактуется как
  `DISABLE`; включение через daemon API добавит status атомарно, а встроенное
  значение `yes` позволит применить политику без миграции conffile.
