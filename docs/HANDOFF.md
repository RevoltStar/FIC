# FIC 2.0: передача контекста

Этот файл хранит актуальный снимок незавершенной работы. Обязательные правила и
границы компонентов находятся в `AGENTS.md`.

## Текущий снимок

- Обновлено: 2026-07-27.
- Ветка: `main`.
- Базовый commit: `0a06a60`.
- Текущая задача: строгая семантика успешного применения политик без
  усложнения публичной модели `Applied`/`Failed`.

## Сделано

- Контракт `Policy::apply()` уточнен: `true` означает проверенное
  persistent-состояние и все физически возможные и безопасные без перезагрузки
  runtime-эффекты. Частичное обязательное применение возвращает `false`.
- Добавлен `SysctlRuntime`: ключ `/proc/sys` строится только из внутреннего
  имени политики, валидируется, открывается с `O_NOFOLLOW`, изменяется прямой
  записью без shell и перечитывается. SYSCTL сначала проверяет наличие runtime-
  ключа, затем исправляет persistent managed-блок и обязательно применяет и
  проверяет runtime. Ошибка runtime после записи persistent-конфигурации
  возвращает `Failed` с диагностикой.
- Добавлен `SshRuntime`: effective-конфигурация проверяется через
  `VerifiedProcessExecutor` и `sshd -T`; активный `ssh.service` или
  `sshd.service` перезагружается проверяемым `systemctl`, после чего состояние
  сервиса проверяется повторно. Ошибка effective-проверки откатывает изменение
  файла; ошибка reload оставляет проверенный persistent-файл, но возвращает
  частичный неуспех.
- Fstab после атомарной записи перечитывается и повторно проверяет требуемые
  параметры. Runtime remount намеренно не выполняется как опасное действие.
- DisplayManager перечитывает записанный конфиг; ModeAndOwner выполняет
  контрольный `stat` после `chown`/`chmod`.
- Не реализованная политика `lock_on_tty_switch` больше не возвращает ложный
  успех: она fail-closed с локализованной ошибкой и честным описанием в GUI.
- Добавлены изолированные тесты SYSCTL runtime и SSH runtime; обновлены
  `fic/README.md` и архитектурные диаграммы.

## Основные измененные зоны

- `fic-common/fic-policy/include/fic/policy/Policy.h`.
- `fic/src/modules/sysctl/Sysctl*`.
- `fic/src/modules/net/submodules/Ssh*`.
- `fic/src/modules/oss/submodules/Fstab.cpp`.
- `fic/src/modules/oss/submodules/DisplayManager/backends/DisplayManagerBackend.cpp`.
- `fic/src/modules/dac/submodules/ModeAndOwner.cpp`.
- `fic/src/modules/oss/submodules/SessionManagement/OSS_lock_on_tty_switch.cpp`.
- `fic/src/scripts/lang/{ru,en}.lang`.
- `tests/sysctl`, `tests/ssh`, `tests/CMakeLists.txt`.
- `fic/README.md`, `docs/architecture-diagrams.md`.

## Проверки

Успешно выполнены:

```bash
cmake -S . -B /tmp/fic2-apply-semantics-build -DBUILD_TESTING=ON
cmake --build /tmp/fic2-apply-semantics-build -j2
ctest --test-dir /tmp/fic2-apply-semantics-build --output-on-failure

cmake --build /tmp/fic2-apply-semantics-build \
  --target ssh_runtime_tests fic -j2
ctest --test-dir /tmp/fic2-apply-semantics-build \
  -R ssh_runtime_tests --output-on-failure
git diff --check
```

Собраны все цели. Из 9 CTest-целей 8 прошли, `admin_socket_tests` собран, но
пропущен из-за запрета sandbox на `bind(AF_UNIX)`. Последняя узкая пересборка
после уточнения обработки ошибок `systemctl` также успешна.

Реальные записи в `/proc/sys`, SSH reload, remount, изменение системных
конфигов, policy apply, device mutation, установка пакетов и запись в
`/opt/fic` не выполнялись. Docker-сборки deb/rpm не запускались.

## Что осталось и риски

- Перед реальным применением SSH-политик администратор должен сохранить hashes
  выбранных `sshd` и `systemctl`, обычно `/usr/sbin/sshd` и
  `/usr/bin/systemctl`. Без них политика корректно завершится ошибкой.
- Runtime SSH рассчитан на поддерживаемые systemd-дистрибутивы. Отдельный
  `sshd`, запущенный вне `ssh.service`/`sshd.service`, автоматически не
  перезагружается.
- Нужен runtime smoke в одноразовой VM: безопасный SYSCTL-параметр,
  `sshd -T`/reload с установленными hashes и проверка частичных отказов.
- Для postcondition Fstab, DisplayManager и ModeAndOwner пока выполнена полная
  компиляция, но нет отдельных изолированных unit-тестов.
- `lock_on_tty_switch` остается не реализованной и при включении намеренно
  возвращает `Failed`.
- Перед merge желательно запустить `admin_socket_tests` вне sandbox и тяжелые
  Debian 12/ALT p11 package builds.
