# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `149ba8d`.

## Current task

- Не терять подробный daemon response при `apply_module` с `ok=false` в GUI.

## Accepted architecture / invariants

- IPC/client failure и валидный daemon response являются разными outcomes.
- `apply_module` с boolean `ok` считается completed operation; поле `ok`
  определяет success/warning presentation, а не transport status.
- Save operations по-прежнему требуют `ok=true`; daemon protocol не изменён.
- Старый `fic::ipc::Client::request()` сохраняет прежний контракт для остальных
  consumers; typed status доступен через additive `requestWithStatus()`.

## Completed

- В `fic-ipc` добавлен typed request result, различающий protocol response и
  client/transport error.
- `PolicyService::saveAndApplyChanges()` возвращает `Completed/ServiceError` с
  сохранённым response для обоих значений daemon `ok`.
- Apply response валидируется до передачи UI; malformed nested result или
  diagnostic классифицируется как service error.
- GUI показывает warning для `ok=false`, сохраняя `message`, `summary`,
  `results`, diagnostic `category` и truncation markers.

## Changed areas

- `fic-common/fic-ipc` client result API.
- GUI `PolicyService` и apply dialog formatting.
- GUI documentation и PolicyService/IPC regression tests.

## Validation

- Ubuntu 26.04 container: full project build — passed.
- `policy_service_tests` — passed.
- `ipc_transport_tests` — passed.
- `ipc_protocol_validation_tests` — passed.
- `git diff --check` выполняется перед завершением.

## Remaining

- Implementation work не осталось.
- Интерактивный GUI dialog вручную не проверялся; его rendering покрыт сборкой,
  а service outcome — regression tests.
