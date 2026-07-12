# fic-cli

`fic-cli` - терминальный клиент FIC 2.0. Компонент предназначен для управления конфигурацией и немедленного применения политик через демон `fic`.

## Назначение

`fic-cli` не изменяет конфигурационные файлы напрямую. Любая операция, которая меняет значение политики, включает политику, отключает политику или применяет политику, отправляется демону через Unix-сокет.

CLI является тонким клиентом над daemon API. Это значит, что права на изменение `/opt/fic/config` и применение политик остаются у `fic`, а терминальная утилита только формирует команду и отображает ответ.

## Socket-подключение

По умолчанию клиент подключается к:

```text
/run/fic/fic.sock
```

Для разработки и тестов путь можно переопределить переменной окружения:

```bash
FIC_SOCKET_PATH=/tmp/fic.sock fic-cli status
```

Переменная обрабатывается в общем IPC-клиенте:

```text
fic-common/fic-ipc/include/fic/ipc/FicIpcClient.h
```

## Общий формат работы

Команда CLI преобразуется в JSON-запрос и отправляется демону. Например:

```bash
fic-cli policy set DAC sudo_timeout 10
```

соответствует IPC-запросу:

```json
{"command":"set_policy_value","module":"DAC","policy":"sudo_timeout","value":"10"}
```

CLI печатает поле `message` из ответа демона. Если демон вернул `ok: false`, процесс завершается с кодом `1`.

## Команды

### help

Печатает справку по командам.

```bash
fic-cli help
```

### status

Проверяет доступность демона.

```bash
fic-cli status
```

Ожидаемый успешный ответ:

```text
fic daemon is running
```

### shutdown

Запрашивает штатную остановку демона.

```bash
fic-cli shutdown
```

### module list

Печатает список модулей, известных демону.

```bash
fic-cli module list
```

### policy list

Печатает список политик для модуля или всех модулей.

```bash
fic-cli policy list all
```

```bash
fic-cli policy list DAC
```

Формат вывода одной политики:

```text
module:submodule:policy ENABLE
```

или:

```text
module:submodule:policy DISABLE
```

### policy set

Устанавливает значение политики.

```bash
fic-cli policy set <module> <policy> <value>
```

Пример:

```bash
fic-cli policy set DAC sudo_timeout 10
```

Команда отправляет демону `set_policy_value`. После успешного изменения демон перечитывает конфигурацию.

### policy enable

Включает политику.

```bash
fic-cli policy enable <module> <policy>
```

Пример:

```bash
fic-cli policy enable DAC sudo_timeout
```

Команда отправляет демону `enable_policy`.

### policy disable

Отключает политику.

```bash
fic-cli policy disable <module> <policy>
```

Пример:

```bash
fic-cli policy disable DAC sudo_timeout
```

Команда отправляет демону `disable_policy`.

### policy apply all

Немедленно применяет все включенные политики.

```bash
fic-cli policy apply all
```

Команда отправляет демону `apply_all`.

### policy apply <module> all

Немедленно применяет все включенные политики одного модуля.

```bash
fic-cli policy apply DAC all
```

Команда отправляет демону `apply_module`.

### policy apply <module> <policy>

Немедленно применяет одну политику.

```bash
fic-cli policy apply DAC sudo_timeout
```

Команда отправляет демону `apply_policy`.

После общей сводки CLI печатает результат каждой политики и вложенные
диагностические записи с временем, уровнем и категорией. В ответ попадают
только записи, прошедшие настроенный в FIC уровень логирования. Если демон
ограничил объем диагностик, CLI выводит `... diagnostics truncated`.

### hash calc

Пересчитывает hash для указанного пути.

```bash
fic-cli hash calc /usr/bin/sudo
```

Команда отправляет демону `calc_hash`.

### lock, unlock, lockstatus

Команды управления блокировкой.

```bash
fic-cli lock
fic-cli unlock
fic-cli lockstatus
```

## Bash completion

Файл completion устанавливается из:

```text
fic/src/scripts/completion/fic
```

В пакетах он устанавливается как completion для `fic-cli`.

## Сборка

Из корня проекта:

```bash
cmake -S . -B build-check
cmake --build build-check --target fic-cli
```

Отдельная сборка компонента:

```bash
cmake -S fic-cli -B build-fic-cli
cmake --build build-fic-cli
```

## Зависимости

Компонент использует:

- C++17;
- SQLite3 и OpenSSL, потому что CLI линкуется с общей логикой FIC;
- nlohmann/json;
- POSIX Unix-сокеты.

## Типовой сценарий

1. Запустить демон:

```bash
fic --socket /tmp/fic.sock --interval 60
```

2. Проверить доступность:

```bash
FIC_SOCKET_PATH=/tmp/fic.sock fic-cli status
```

3. Изменить значение политики:

```bash
FIC_SOCKET_PATH=/tmp/fic.sock fic-cli policy set DAC sudo_timeout 10
```

4. Включить политику:

```bash
FIC_SOCKET_PATH=/tmp/fic.sock fic-cli policy enable DAC sudo_timeout
```

5. Применить политику немедленно:

```bash
FIC_SOCKET_PATH=/tmp/fic.sock fic-cli policy apply DAC sudo_timeout
```

## Важные правила разработки

- CLI не должен писать в `/opt/fic/config` напрямую.
- Новая CLI-команда должна быть тонкой оберткой над IPC-командой демона.
- Если для новой операции требуется изменение конфигурации, сначала нужно добавить команду в `fic`, затем вызвать ее из `fic-cli`.
- Ошибки демона должны проходить до пользователя без потери текста `message`.
