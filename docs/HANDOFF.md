# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `7fda977`.

## Current task

- Исправить P0 path resolution `custom_mode_and_owner`, сохранив штатные
  intermediate symlink вроде usrmerge и запретив attacker-controlled цепочки.

## Accepted architecture / invariants

- Built-in DAC policies сохраняют прежний `Standard` resolution.
- Только `custom_mode_and_owner` использует проверку каждого intermediate
  компонента и по-прежнему отвергает final symlink.
- Root-owned sticky directory допустим как namespace boundary; следующий
  компонент всё равно проверяется по descriptor, owner, type и mode.

## Completed

- Добавлен component-by-component descriptor traversal для custom policy.
- Trusted root-owned intermediate symlink поддерживается, его target повторно
  проходит полную проверку от `/`.
- Непривилегированный owner либо group/other-writable intermediate directory
  приводит к fail-closed отказу до `fchmod`/`fchown`.

## Changed areas

- `fic-common/fic-core`: безопасный режим `PolicyPathResolution`.
- `fic/src/modules/dac/mode_and_owner`: явный выбор режима custom policy.
- `tests/fic/modules/dac/ModeAndOwnerTests.cpp`.

## Validation

- ALT p11 builder container: `mode_and_owner_tests` built and passed for all
  five target profiles: Debian 12/13, Ubuntu 24.04/26.04, ALT p11, включая
  regular, final symlink, trusted symlink/usrmerge, writable и unprivileged-owned
  intermediate directory, unchanged victim.

## Remaining

- Свежая host-конфигурация CMake недоступна: отсутствует `libsystemd`; проверка
  выполнена в изолированном ALT p11 builder image.
- После этого коммита остаются задачи 2-6 из пользовательского списка.
