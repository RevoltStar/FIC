# Maintenance admission — M1 implementation status

## Реализованная граница

Перед write-capable journal initialization следующие standalone-команды получают
тот же неблокирующий `/run/fic/daemon.lock`, что daemon mode:

* `dm-prerm-prepare release`, `desktop-prerm-prepare release`,
  `pam-provider-prerm-prepare release`, `pam-password-prerm-prepare release`;
* `ensure-config`, `ensure-config-first-install`, `incident-init`,
  `bootstrap-pam-password-slots`;
* `incident-pam-alt attach/detach`.

Guard удерживается в `main` до завершения операции. Не передаётся через environment
или дочерним maintenance writers. Занятый/недоверенный lock — отказ без journal load,
без release/containment и без fallback на IPC socket. Custom socket не меняет lock.
Неизвестные maintenance command/action отвергаются до dispatch.

Порядок: instance admission → operational journal load → backend resource locks →
mutation/finalization → уничтожение guard. Backend не захватывает instance lock
после своего resource lock. Пока нет package-session, независимые shell children
получают и освобождают lock по отдельности: **межкомандный package gap не закрыт**.

## Read-only pre-stop preflight

Четыре `*-prerm-prepare preflight` используют отдельный `MutationJournal` с
`validatePersistentStateReadOnly()`, а не operational singleton `tryGet()`.
Проверка не bootstrap/recover/migrate journal или witness. Virgin/missing/corrupt
provenance может отказать; байты persistent state при этом не меняются. После stop
release открывает свежий operational journal после собственного admission.
Preflight не является разрешением действовать по устаревшему snapshot.

## Отдельно сериализованные и read-only маршруты

`pam-alt-faillock status/enable/disable` и
`pam-alt-pwhistory status/prepare/enable/disable` пока сохраняют существующие
per-resource topology locks. Их scope — соответствующая topology, не whole journal
или package lifecycle. Trust sync сохраняет hash-store serialization.

`check-config`, `wait-daemon`, `incident-pam-verify`,
`incident-pam-prove-detached`, `validate-pam-slots-before-attach` и
`incident-pam-alt status` не получают общий writer guard. Это не разрешение включить
в них initialization/repair. Проверки с чисто диагностическими runtime artifacts
не должны менять policy/journal/security state.

## Незавершённая часть M1

Свободный lock не доказывает stopped legacy writers. В текущей реализации ещё нет
интегрированного package-session, persistent lifecycle fence/startup gate,
процессного/cgroup proof, ownership-safe masks, закрытого install/abort/recovery и
production finalizer. Shell DEB/RPM sequence ещё не перенесена в coordinator;
исходные package admission defects из `daemon-singleton.md` остаются до этого этапа.
Нельзя считать новый guard полной package safety.

Принятый retry/recovery contract:
[maintenance-finalizer-retry-lifecycle.md](maintenance-finalizer-retry-lifecycle.md).
Store, retry policy и native fixtures не заменяют production proof-controller.

## Проверки

`maintenance_preflight_native`: реальные четыре entrypoints на virgin/corrupt
journal, persistent snapshots неизменны. Только opt-in disposable root container.
`daemon_singleton_startup_native`: настоящий holder блокирует daemon default/custom
socket и standalone mutators до system changes. Unit classification tests фиксируют
закрытый dispatch; основные singleton process tests — contention/crash/restart.

Store/retry tests отдельно проверяют typed phases, CAS, trusted bounded reads,
durable cooldown и структурную блокировку. Они не доказывают безопасность ещё
неподключённого package coordinator. Полную cross-platform package matrix нельзя
заменять этими тестами.
