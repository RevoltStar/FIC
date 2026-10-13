# SUDO apply/rollback: актуальные требования

Это уточнение задания на три последовательных этапа: A — global Defaults
ownership, B — integration scoped Defaults, C — reversible authentication.
Реализация и проверки ещё не завершены. Авторитетный итоговый контракт после
приёмки должен быть отражён в `rollback.md`.

## Активный provider

FIC поддерживает реальный активный provider и никогда автоматически не
переключает `/usr/bin/sudo` или alternatives. Должны быть доказаны provider,
версия, конфигурационный маршрут и соответствующий native validator.
Unknown provider, неизвестная версия/семантика или смена provider во время
операции приводят к fail-closed.

Для classic sudo пять global Defaults имеют journal-bound ownership в
`/etc/sudoers.d/99-fic.conf`, подключённом каноническим EOF-блоком:

```sudoers
#@FIC_INCLUDE_BEGIN
@include /etc/sudoers.d/99-fic.conf
#@FIC_INCLUDE_END
```

Для sudo-rs доказанное отсутствие механизма `exempt_group` означает успешный
`VerifiedByConstruction` для `sudo_exempt_group_disable`: ни выдуманного
Defaults, ни фиктивного mutation record. Доказанный безусловный `env_reset`
имеет ту же классификацию для `sudo_env_reset=ENABLE`; противоречащее значение
нельзя объявлять выполненным. Native proof и поддерживаемая версия обязательны.

Required-зависимость authentication от exempt-group blocker сохраняется для
classic sudo и не требует включения бессмысленной политики для sudo-rs.
Неизвестные capabilities не позволяют снять security dependency.
Аналогично должны быть проверены остальные зависимости от этого blocker.

## Ownership и освобождение

Каждое записанное global Defaults принадлежит отдельной policy mutation.
Идентичность общего контейнера не зависит от порядка отключения владельцев.
Prepared provenance долговечна до первого изменения файла. Сначала записывается
owned файл, затем EOF include, затем native syntax и semantic postconditions,
затем Applied. Ошибки не уничтожают unresolved provenance.

Последний владелец сначала делает файл инертным, долговечно удаляет только
доказанный include, проверяет весь граф и лишь затем освобождает отключённый
файл conditional-delete. Чужие повторные includes могут препятствовать удалению
контейнера; их нельзя удалить по собственной инициативе.

Authentication получает typed transformations и обратимые wrappers с точными
оригинальными байтами внутри файлов и digest/ID/path proofs в journal.
Snapshot чужого файла не используется как rollback payload. Поддержка aliases,
continuation, tag inheritance и Defaults проверяется до любых mutations.
Scoped/authentication wrappers не могут независимо владеть одной активной
строкой; оба порядка apply/disable требуют тестов и безопасного отказа при
неразрешимой координации.

Смена provider при существующих FIC-owned артефактах должна сохранять
provenance и возможность безопасного release; нельзя молча бросить ownership
при переходе к VerifiedByConstruction.

## Обязательная native матрица

Podman: Debian 12, Debian 13, Ubuntu 24.04, Ubuntu 26.04 с активным sudo-rs,
Ubuntu 26.04 с classic sudo, ALT p11. Alternatives разрешено переключать
исключительно в disposable тестовом контейнере.

Проверяются explicit/include-dir semantics `.conf`, реальное разрешение
Defaults, требование пароля тестовому пользователю, неизменность command
permissions, rollback и crash recovery на каждой долговечной границе.
Для sudo-rs отдельно проверяются ограничения аргументов при line continuation:
SUCCESS валидатора сам по себе не доказывает безопасность. Для непроверенной
версии/конструкции transformation запрещена.

Текущие первичные источники для исследования:
[sudoers grammar](https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in),
[visudo](https://github.com/sudo-project/sudo/blob/main/docs/visudo.man.in),
[sudo-rs provider differences](https://github.com/trifectatechfoundation/sudo-rs),
[sudo-rs releases](https://github.com/trifectatechfoundation/sudo-rs/releases).
