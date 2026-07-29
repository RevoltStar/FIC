# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-07-29.
- Ветка: `main`.
- Базовый commit: `d875495`.
- Текущая задача: исправление post-check политики `ssh_root_login` для алиасов
  OpenSSH `prohibit-password` и `without-password`.
- Исправление завершено и проверено, изменения не закоммичены.

## Сделано

- В `SshRuntime` добавлено семантическое сравнение скалярного значения
  `PermitRootLogin`.
- `prohibit-password` и `without-password` считаются эквивалентными, поскольку
  OpenSSH 10 выводит через `sshd -T` второй алиас даже при записи первого.
- Нормализация ограничена SSH-параметром `PermitRootLogin`; общие
  `PolicyTypeValue` и `FixedPolicyTypeValue` не изменялись.
- Семантически разные значения `no`, `forced-commands-only`,
  `prohibit-password`/`without-password` и `yes` при глобальной post-check
  остаются различными. Более строгое значение не выдается за точное совпадение.
- Добавлены положительный регрессионный тест алиаса и отрицательный тест,
  запрещающий считать `forced-commands-only` эквивалентом
  `prohibit-password`.
- Поведение алиаса описано в `fic/README.md`.

## Измененные файлы

- `fic/src/modules/net/submodules/SshRuntime.cpp`;
- `tests/ssh/SshRuntimeTests.cpp`;
- `fic/README.md`;
- `docs/HANDOFF.md`.

## Локальные проверки

Успешно выполнены:

```bash
git diff --check
cmake -S . -B /tmp/fic2-ssh-alias-fix -DBUILD_TESTING=ON
cmake --build /tmp/fic2-ssh-alias-fix --target ssh_runtime_tests fic -j2
ctest --test-dir /tmp/fic2-ssh-alias-fix --output-on-failure \
  -R '^(ssh_runtime_tests|ssh_policy_static_checks)$'
```

Обе выбранные CTest-проверки прошли, daemon `fic` собран успешно.

## Интеграционная проверка

Исправленный daemon временно установлен на Debian-хост `172.17.1.105` с
OpenSSH `10.0p2 Debian-7+deb13u4`. Проверен исходный проблемный сценарий:

```text
PermitRootLogin=yes # fic integration deviation
```

Политика с ожидаемым `prohibit-password` вернула `FIC_RC=0`; после применения
реальный `sshd -T` показал `permitrootlogin without-password`. Это подтверждает,
что исправлена именно post-check канонизированного значения. Новое независимое
SSH-подключение после применения успешно.

После теста исходный `/opt/fic/bin/fic`, `NET.conf`, `commandhash.txt`,
`sshd_config` и каталог `sshd_config.d` восстановлены и побайтово сравнены с
резервными копиями. Сервисы `ssh` и `fic` активны, `sshd -t` успешен, все
SSH-политики снова отключены, финальное независимое SSH-подключение успешно.

Исходный установленный daemon оставлен на машине: рабочая версия исправления
не разворачивалась постоянно. Артефакты интеграционного теста находятся в
root-only каталогах `/var/tmp/fic-ssh-integration-20260729` и
`/var/tmp/fic-ssh-alias-fix-20260729`.

## Что осталось

- Просмотреть diff и закоммитить исправление.
- Развернуть новую сборку штатным пакетным способом, если исправление требуется
  на тестовой машине постоянно.
