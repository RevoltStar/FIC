# FIC 2.0: передача контекста

Этот файл хранит текущее состояние работы между чатами. Он не является журналом
всей разработки и не заменяет `AGENTS.md` или архитектурную документацию.
Следующий агент должен сначала прочитать этот файл, затем проверить фактическое
состояние через `git status`.

## Текущий снимок

- Обновлено: 2026-06-26.
- Ветка: `main`.
- Базовый commit: `befcfd6` (`Исправляем баги сокетов`).
- Текущая задача: исправить boot-запуск FIC после установки Debian-пакетов и
  перезагрузки.

## Что было обнаружено на машине `172.17.1.105`

- Установлены пакеты `fic`, `fic-cli`, `fic-dick`, `fic-gui`,
  `fic-session-agent` версии `0.1.0`.
- После reboot GUI показывал ошибку:
  `connect(/run/fic/fic.sock) failed: Нет такого файла или каталога`.
- `/run/fic` был создан корректно: `root:fic 0770`, но сокеты отсутствовали.
- `fic.service` и `fic-device.service` были `inactive (dead)`.
- `journalctl -b` показал ordering cycle:
  `fic-device.service: Found ordering cycle on fic.service/start` и
  `Job fic.service/start deleted to break ordering cycle`.
- Цикл возникал из-за сочетания `WantedBy=multi-user.target` и
  `After=multi-user.target` у `fic.service`, плюс цепочки
  `fic_get_device_udev_info.service -> fic-device.service -> fic.service`.
- Также найден packaging/runtime дефект: установленный
  `/etc/udev/rules.d/99-fic-devices.rules` имел права `0777`, из-за чего
  `systemd-udevd` предупреждал, что файл executable и world-writable.

## Сделано

- Удален лишний `After=multi-user.target` из:
  - `fic/src/scripts/service/fic.service`;
  - `fic/src/scripts/service/fic_get_device_info.service`;
  - `fic/src/scripts/service/fic-notify.service`.
- Для CMake install udev rules добавлены явные права `0644` через
  `FILE_PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ`.
- В Debian 10/11/12 packaging после копирования udev rules добавлен
  `chmod 0644` для файлов в package root.
- В ALT p11 RPM packaging после копирования udev rules добавлен такой же
  `chmod 0644`.
- На машине `172.17.1.105` никаких правок, рестартов сервисов или package
  install не выполнялось; использовалась только диагностика.

## Измененные файлы

- `fic/src/scripts/service/fic.service`
- `fic/src/scripts/service/fic_get_device_info.service`
- `fic/src/scripts/service/fic-notify.service`
- `fic/CMakeLists.txt`
- `packaging/deb/build-fic-debian10-deb.sh`
- `packaging/deb/build-fic-debian11-deb.sh`
- `packaging/deb/build-fic-debian12-deb.sh`
- `packaging/rpm/build-fic-alt-p11-rpm.sh`
- `docs/HANDOFF.md`

## Проверки

Выполнено:

```bash
git status --short
rg -n "After=multi-user.target" fic/src/scripts/service packaging/deb packaging/rpm fic/CMakeLists.txt
bash -n packaging/deb/build-fic-debian10-deb.sh packaging/deb/build-fic-debian11-deb.sh packaging/deb/build-fic-debian12-deb.sh packaging/rpm/build-fic-alt-p11-rpm.sh
git diff --check
```

Результат:

- `After=multi-user.target` больше не найден;
- shell-синтаксис packaging-скриптов корректен;
- `git diff --check` без ошибок.

Не выполнялось по просьбе пользователя:

- CMake configure/build;
- сборка deb/rpm пакетов;
- установка пакетов;
- runtime-рестарты сервисов на тестовой машине.

## Важные замечания

- В текущем workspace на Windows/WSL `stat` может показывать `0777` для
  исходных файлов независимо от git mode. В git эти unit/udev файлы сохранены
  как `100644`; packaging и CMake теперь дополнительно принудительно задают
  `0644` для udev rules в staging/install.
- После пересборки и установки пакетов нужно повторить reboot/runtime-проверку:
  `systemctl status fic.service fic-device.service`,
  `stat -c '%U %G %a %n' /run/fic /run/fic/fic.sock /run/fic/fic-device.sock`,
  `fic-cli status`, `fic-cli device root`, запуск `fic-gui`.
