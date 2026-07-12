# FIC 2.0: передача контекста

Этот файл хранит текущее состояние работы между чатами. Он не является журналом
всей разработки и не заменяет `AGENTS.md` или архитектурную документацию.

## Текущий снимок

- Обновлено: 2026-07-12.
- Ветка: `main`.
- Базовый commit: `befe124`.
- Текущая задача: добавить диагностику выполнения `Policy::apply()` в ответы
  daemon API без хранения request-state в объектах `Policy`.

## Сделано

- В `Logger` добавлен `ScopedCapture`: RAII-захват отфильтрованных записей
  текущего потока с восстановлением предыдущего capture при выходе из scope.
- Захват выполняется после проверки `GLOBAL/log_level`, но до файловой записи;
  ошибка capture не препятствует основному логированию.
- Один capture ограничен 128 записями и 64 КиБ.
- В `PolicyApplyResult` добавлены структурированные `diagnostics` с полями
  `timestamp`, `level`, `category`, `message` и признак
  `diagnosticsTruncated`.
- Три пути применения политики сведены к общему `executePolicy()`. Capture
  создается строго вокруг одного `Policy::apply()`, после чего diagnostics
  переносятся в результат этой политики.
- Исключение одной политики преобразуется в `Failed` и диагностическую запись,
  поэтому не прерывает формирование результата остальных политик модуля или
  `apply_all`.
- Daemon API возвращает `diagnostics` и `diagnostics_truncated` внутри каждого
  элемента `results`; общий объем сериализованных diagnostics ограничен
  256 КиБ и отражается также верхнеуровневым `diagnostics_truncated`.
- CLI печатает вложенные диагностические записи после результата политики.
- GUI показывает diagnostics в раскрываемом поле Details.
- Обновлены README демона, CLI, GUI и диаграмма применения политики.

## Измененные файлы

- `fic-common/fic-core/include/fic/core/Logger.h`
- `fic-common/fic-core/src/Logger.cpp`
- `fic-common/fic-policy/include/fic/policy/PolicyApplyResult.h`
- `fic/src/core/main_function.cpp`
- `fic/src/main.cpp`
- `fic-cli/src/main.cpp`
- `fic-gui/src/mainwindow.cpp`
- `fic/README.md`
- `fic-cli/README.md`
- `fic-gui/README.md`
- `docs/architecture-diagrams.md`
- `docs/HANDOFF.md`

## Проверки

Выполнено успешно:

```bash
cmake -S . -B build-check
cmake --build build-check -j2
git diff --check
```

Полная сборка завершилась на 100% и собрала `fic`, `fic-cli`, `fic-gui`,
`fic-session-agent`, `fic-dick` и общие библиотеки.

Выполнена runtime-проверка на тестовом стенде `172.17.1.105`:

- `fic-cli policy apply GLOBAL log_level` завершился успешно и вернул
  `applied=1`;
- для отрицательного сценария `NET/ssh_port` временно переключался в `ENABLE`
  со значением `not-a-port` непосредственно в `/opt/fic/config/NET.conf`;
- `fic-cli policy apply NET ssh_port` вернул код `1`, `failed=1` и вложенную
  диагностику `ERROR`: `Invalid policy value for ssh_port: not-a-port`;
- trap восстановил исходный конфиг; отдельно подтверждены
  `ssh_port.status=DISABLE`, `ssh_port.value=22`, права `root:fic 0660`,
  отсутствие временного backup и активное состояние `fic.service`.

Автоматизированных unit/CTest-тестов для Logger и policy apply в проекте сейчас
нет.

## Что осталось и риски

- Runtime подтвержден для успешного и ошибочного `apply_policy` через CLI.
  Отдельно не проверялись `apply_module`, `apply_all`, достижение лимитов и
  визуальное отображение в GUI.
- При текущем значении `GLOBAL/log_level=WARN` успешные INFO/DEBUG-шаги не
  возвращаются — это намеренно совпадает с фильтрацией файлового журнала.
- `ScopedCapture` использует thread-local контекст и захватывает записи только
  текущего потока. Если реализация политики начнет логировать из созданных ею
  worker threads, им потребуется явная передача контекста.
- Содержательная причина обычного `apply()==false` по-прежнему зависит от
  диагностик; долгосрочно стоит заменить `bool apply()` на явный
  `PolicyApplyOutcome`, не зависящий от уровня логирования.
