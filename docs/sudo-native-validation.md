# SUDO: текущая native проверка

Scoped/authentication integration остаётся отдельным обязательным gate.
Все описанные
эксперименты выполнялись в disposable Podman, без host `/etc`, PAM или
security mounts. Изменений host sudo provider нет.

## Реально выполненные scalar gates

| Платформа | Активный provider/version | Scalar native gate |
|---|---|---|
| Debian 12 | classic 1.9.13p3 | PASS |
| Debian 13 | classic 1.9.16p2 | PASS |
| Ubuntu 24.04 | classic 1.9.15p5 | PASS |
| Ubuntu 26.04 | classic 1.9.17p2 | PASS |
| Ubuntu 26.04 | sudo-rs 0.2.13-0ubuntu1.2 | PASS behavioral gate |
| ALT p11 | classic 1.9.17p2 | PASS |

Classic gate — `tests/integration/sudo/global-native-gate.sh`: реальные
production policy apply, повторное применение, смена значения, native
effective Defaults, игнорирование `.conf` в includedir и явное подключение
на EOF, contextual Defaults, отказ при foreign suffix, независимый rollback
и точное восстановление исходных байтов основного файла.

sudo-rs не показывает Defaults в `sudo -l`; использование classic assertion
первоначально остановило gate. Заменяющая native проверка —
`rust-behavior-native-gate.sh`: реальный PATH команды, удаление переменной
окружения, число запросов неверного пароля (3→4), разрешение без нового
пароля после успешной аутентификации при timeout10 и отказ при timeout0.
Также проверены `.conf`/EOF через PATH, repeated apply, foreign suffix
и независимый rollback. `env_reset`/`exempt_group` создают ноль records.

`provider-transition-native-gate.sh` PASS на Ubuntu26: classic ownership
env/exempt безопасно освобождается после перехода к sudo-rs; passwd_tries
остаётся owned. Последний release восстанавливает точные исходные байты.
Возврат к classic создаёт и освобождает настоящую env_reset ownership.
Alternatives переключаются исключительно внутри тестового контейнера.

Native drivers собраны отдельно в matching distro containers из настоящих
production исходников. Локальные полные logs находятся в ignored
`build-sudo-native/`: Debian12 `debian12/final-scalar.log`, остальные
`min-<platform>/final-scalar*.log`, Ubuntu26 дополнительно
`provider-transition-gate.log`; crash logs — `crash-gate*.log`.

## Существенные платформенные различия

* Classic использует mode0440; ALT native visudo требует0400. Cached ALT
  builder потребовал восстановления RPM permissions/owners, а disposable
  `/` —0755; точный package fragment `99-sudopw` нормализован0400 только
  внутри контейнера. Packaged ALT не разрешает root команды через sudo:
  global gate добавляет отдельное fixture rule. User authorization probes
  включают native `control sudo wheelonly` и добавляют fixture user в wheel.
* Для sudo-rs проверены unconditional env_reset и отказ native visudo от
  global/negated/contextual exempt_group. Это provider guarantee, а не
  записанный FIC-owned параметр или пропущенная проверка.
* В протестированной sudo-rs конфигурации более поздний global timeout10
  перекрывает ранее загруженный user timeout0; native timestamp cache
  проверен реальными командами. Classic сохраняет приоритет contextual
  значения в аналогичной проверке. Чужие contextual байты не удаляются.
* sudo-rs отвергает continuation внутри command arguments. Continuation
  после запятой command list принимает; реальные разрешённые/запрещённые
  команды подтвердили сохранение аргументов и inherited NOPASSWD. Этот
  результат не допускает произвольные multiline authentication rewrites.

## Оставшиеся проверки

`crash-native-gate.sh` PASS по всем шести строкам матрицы: 15 process-crash
boundaries на строку, всего90. Принудительный `_exit` проверяет fresh/refresh
до Prepared, после Prepared, после file/include/postcondition, last release
после file/inert/detach/delete и independent release при surviving owner.
Каждый restart подтверждает native visudo, recovery и точный final main hash.

Полная project build PASS. Первый host sandbox CTest запуск: 11 failures,
4 skips из181 (socket/NSS ограничения и root-only fixtures). Повтор всех
failed fixture tests вне sandbox без root-only display-manager теста PASS;
три socket skipped tests PASS после повторного запуска. Два root-only tests
(`display_manager_transaction_tests`, `command_hash_batch_tests`) собраны
и выполнены в Debian12 Podman без DAC_OVERRIDE/DAC_READ_SEARCH: PASS2/2.
После последнего orphan-include hardening полный non-root CTest вне sandbox
PASS179/179; root-only Podman PASS2/2. Итого все181 test cases выполнены
успешно в подходящих окружениях; это два отдельных CTest запуска. Дополнительные global recovery и
malformed-journal regressions после полной сборки также PASS.

Полный scoped/authentication contract и финальная валидация B/C остаются.
Успех scalar gates не означает завершение всей задачи A/B/C.
