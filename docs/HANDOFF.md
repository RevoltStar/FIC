# FIC: передача контекста

## Current base

- Ветка: `main`.
- Базовый commit задачи: `da39884b35fd83c3d6215eb2158d276cdb4d1ead`.

## Current task

- Устранение ложных `WARN` при штатном apply/reconciliation в
  `FirewallBackend`.

## Accepted architecture / invariants

- Первичное создание, повторный refresh и восстановление отсутствующих
  FIC-managed nftables tables являются штатными операциями.
- Удаление stale FIC-managed table логируется как значимое изменение, но не
  как ошибка; нейтрализация чужих filtering chains сохраняет `WARN`.
- Ошибки nft execution и postcondition поднимаются из backend и логируются
  вызывающим policy/reconciliation слоем как `ERROR`.

## Completed

- Routine `missing` и `refreshing` сообщения `FirewallBackend` переведены с
  `WARN` на `DEBUG`.
- Удаление stale FIC-managed table переведено с `WARN` на `INFO`.
- Static contract фиксирует уровни всех изменённых backend-сообщений.

## Changed areas

- `fic/src/modules/firewall/FirewallBackend.cpp`.
- `tests/fic/modules/firewall/static_checks.py`.

## Validation

- `firewall_static_checks` — успешно.
- `firewall_tests` — успешно.
- `git diff --check` — успешно.

## Remaining

- Изменения не закоммичены.
- Новая сборка не развёртывалась; live nftables apply не выполнялся.
