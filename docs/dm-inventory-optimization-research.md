# DM inventory transport research

Дата проверки 2026-11-27. База задач a0fae90b. Production-изменения ограничены
клиентской инвентаризацией unit-файлов и наблюдательным режимом без PackageQuery.
Оптимизация show в production в этой работе не реализована.

## Доказательная база

История a0f5ff85, 52dbe7ba и 3eab56df закрепляет установленные, выбранные и
работающие DM, независимые greeter-сессии, нестандартные имена служб, исключение
неинстанцированных шаблонов и повторную инвентаризацию перед commit.
Проверены текущие пять платформенных профилей и shipped fic.service. Scope
apply сейчас только валидирует configured intent; native autologin reconciliation
вызывается disable_autologin. Required-зависимости сохранены.

STATIC. В upstream systemd v252, v255, v257, v258 и v259 install_client_side()
выбирает клиентский режим при непустом arg_root. Клиентский list-unit-files
вызывает unit_file_get_list с корнем; обработчик ListUnitFiles в manager
использует тот же механизм обхода. Runtime list-units/show остаются обращениями
к manager. Следовательно, --root=/ переносит обход на отдельный процесс,
сохраняя стоимость чтения файлов. Это вывод из versioned upstream; полный
аудит vendor patchsets не проводился.
[systemctl-util v252](https://github.com/systemd/systemd/blob/v252/src/systemctl/systemctl-util.c),
[list-unit-files v255](https://github.com/systemd/systemd/blob/v255/src/systemctl/systemctl-list-unit-files.c),
[manager v252](https://github.com/systemd/systemd/blob/v252/src/core/dbus-manager.c),
[systemctl-util v259](https://github.com/systemd/systemd/blob/v259/src/systemctl/systemctl-util.c).

Shipped daemon работает в системном root без RootDirectory/PrivateMounts.
Executors очищают environment. Эквивалентность предполагает одинаковые unit-file
views у FIC и manager. Администраторские root/mount/unit-path overrides
требуют собственной проверки. FIC не меняет namespace и не переключается
обратно на тяжёлый серверный обход при ошибке.

## Native результаты

RUNTIME. Отдельные privileged Docker-контейнеры с настоящим systemd PID 1,
private cgroup namespace, без сети при запуске и без host bind mounts.
Фикстуры создают enabled, enabled-runtime, disabled, masked, alias,
generated через generator, transient через systemd-run, template и instance,
а также службу с нестандартным именем. Сравниваются все имена/состояния,
которые парсит FIC, и включение instance через list-units. Все сравнения
на доступных трёх платформах совпали. Это проверка транспорта; настоящий
графический вход и запуск display managers не выполнялись.

| Платформа | systemd | Строк unit-files | Сравнение |
| --- | --- | ---: | --- |
| ALT p11 | 258.9-alt1 | 172 | PASS |
| Ubuntu 24.04 | 255.4-1ubuntu8.19 | 130 | PASS |
| Ubuntu 26.04 | 259.9-0ubuntu0.1 | 149 | PASS |
| Debian 12 | UNKNOWN | — | native image не подготовлен |
| Debian 13 | UNKNOWN | — | native image не подготовлен |

Debian APT остановился на загрузке main Packages index через HTTP, затем
через HTTPS с доверенным CA и прямыми именами вместо by-hash. Ограниченная
повторная попытка также не завершилась. Mocked-проверки не заменяют эти
два отсутствующих native результата. Ошибка Windows Docker credential helper
при повторной подготовке обойдена временным пустым Docker config для публичных
образов; настройки пользователя не менялись.

Конкурентный контрольный systemctl show --property=Version выполнялся во время
трёх обходов каждой разновидности. Значения ниже включают стоимость старта
процесса и транспорта, без искусственного HDD throttling.

| Платформа | Максимум probe при server, мс | При client, мс | Server >250 мс | Client >250 мс |
| --- | ---: | ---: | ---: | ---: |
| ALT p11 | 445.1 | 18.3 | 3 | 0 |
| Ubuntu 24.04 | 386.3 | 21.9 | 3 | 0 |
| Ubuntu 26.04 | 424.8 | 13.6 | 3 | 0 |

Время самого обхода осталось сопоставимым. Эти измерения подтверждают механизм
задержки PID 1 на данных снимках. Корреляция каждого исторического
DAEMON_UNAVAILABLE с этим обходом и поведение боевой ВМ не измерялись.

Fixtures и полный JSON с временами трёх прогонов находятся в
tests/integration/dm-inventory/. Повторяемая команда приведена в README.

## Пакетный show

RUNTIME. После объединения unit-files и loaded services использован тот же набор
конкретных юнитов, исключены неинстанцированные шаблоны. Запрошены ровно Id,
Names, LoadState, ActiveState, Description, ExecStart, UnitFileState. Ответы
поштучных и пакетных вызовов совпали после сопоставления по Id; повторяющиеся
aliases проверяются на равенство, времена выполнения и PID не запрашиваются.
Измерение одно на вариант, с тёплым filesystem cache; статистики cold boot нет.

| Платформа | Конкретных имён | Поштучно, с | По 32, с | Запусков systemctl |
| --- | ---: | ---: | ---: | --- |
| ALT p11 | 156 | 1.813 | 0.614 | 156 → 5 |
| Ubuntu 24.04 | 131 | 1.542 | 0.406 | 131 → 5 |
| Ubuntu 26.04 | 138 | 2.345 | 0.720 | 138 → 5 |

Количество запусков соответствует явным subprocess invocation в fixture.
Фактические D-Bus сообщения отдельно не трассировались. Время контрольного
probe измерено для list-unit-files, не для вариантов show.

STATIC. systemctl show перебирает имена и вызывает show_one/bus_map_all_properties.
Один batch устраняет процессы и повторное соединение, но сохраняет чтения
для отдельных объектов. Он не даёт атомарный snapshot всех служб.
[systemctl-show v259](https://github.com/systemd/systemd/blob/v259/src/systemctl/systemctl-show.c).

RUNTIME. Batch с существующим и отсутствующим юнитами на трёх снимках вернул
exit 0, а отсутствующий объект имел LoadState=not-found. Будущий parser обязан
проверять полноту каждого блока, связь Id/Names с запросами и существующие
правила LoadState. Нельзя принимать exit 0 как достаточное доказательство.
Ошибки доступа к одному объекту и смена owner manager не инъецировались native;
их нужно покрыть детерминированными тестами будущей реализации.

## Сравнение вариантов

| Вариант | Производительность | Эквивалентность | Ограничения | Риск регрессии | Сложность |
| --- | --- | --- | --- | --- | --- |
| Текущий поштучный show | N процессов | Текущий эталон | Повторный startup/transport для каждого объекта | Минимальный | Уже реализован |
| show batches по 32 | В native около 3× быстрее, ceil(N/32) процессов | Совпадение выбранных полей на трёх снимках | Нужны разделение блоков, aliases, полнота и общий fail-closed при partial error | Умеренный | Локальный parser и bounded dispatch |
| Прямой D-Bus | Теоретически ноль systemctl child для свойств, O(N) object reads | Достижима с полным прежним unit set | Новые typed parsing, connection owner и error handling; LoadUnit/GetUnit semantics нужно повторить | Выше | Существеннее batching |
| Только активные/именные DM | Мало запросов | Неэквивалентно | Теряет inactive selected, нестандартный enabled unit и inactive custom unit с известным ExecStart | Высокий | Малая ценой потери coverage |
| ListUnits вместо всей union | Убирает show для unloaded files | Неэквивалентно | Не видит ещё не загруженный нестандартный сервис; current show сам получает его свойства | Высокий | Умеренная |
| Убрать повторные инвентаризации | Теоретически сокращает проходы | Между preflight и commit неэквивалентно | Теряет смену установки/route во время native write/verify | Высокий | Нарушает текущий transaction contract |
| Сохранить реализацию | Нет выигрыша | Полная | Сотни child processes остаются | Минимальный | Нулевая |

Для наблюдательной политики фильтрация может в будущем выбирать live/selected
кандидатов, но только после доказательства полноты alias/default file/greeter
и enabled custom-service routes. Фильтрация лишь по basename юнита пропускает
custom.service с ExecStart=/usr/bin/sddm. Для полного autologin inventory
нельзя исключить inactive custom DM только потому, что он пока не запущен.

D-Bus Manager ListUnits описывает загруженные units; Service.ExecStart принадлежит
другому интерфейсу и требует дополнительных properties. ListUnits не заменяет
полный текущий inventory. ListUnitsByPatterns также не делает весь конфигурационный
граф атомарным.
[systemd D-Bus API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html).

Сходные решения изучены как существующие инженерные подходы. go-systemd
предоставляет ListUnitFilesByPatterns; Cockpit использует собственный D-Bus
слой управления службами. Их контракты не являются доказательством эквивалентности
FIC и не требуют заимствования их архитектуры.
[go-systemd](https://github.com/coreos/go-systemd/blob/main/dbus/methods.go),
[Cockpit services](https://github.com/cockpit-project/cockpit/blob/main/pkg/systemd/services.jsx).

Upstream issue 20328 отдельно фиксирует медленный list-unit-files, включая
прямые ListUnitFiles вызовы. Issue OpenSCAP 2012 иллюстрирует опасность
обращения с шаблонами как с конкретными unit objects. Это внешние сообщения,
а не измерения текущих FIC-систем.
[systemd 20328](https://github.com/systemd/systemd/issues/20328),
[OpenSCAP 2012](https://github.com/OpenSCAP/openscap/issues/2012).

## Рекомендация

Следующим отдельным изменением реализовать bounded batching show с сохранением
полной текущей union unit names, тех же полей, доверенных executable checks,
logind и обязательного повторного inventory перед commit. Начать с 32 имён
как проверенного экспериментального размера, затем закрепить limits output,
partial failures, alias deduplication и coverage unit-to-block regression-тестами.
Два Debian native gates нужно завершить перед заявлением пятидистрибутивной
проверенности batching. Уменьшение самого набора юнитов, прямой D-Bus и
reuse snapshots требуют отдельного обоснования. В данной работе их production
реализации нет.
