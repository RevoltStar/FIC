# Maintenance admission

Текущий authoritative lifecycle: [package-lifecycle.md](package-lifecycle.md).
Автономных policy rollback entrypoints больше нет: ownership освобождает только
работающий daemon через `prepare-uninstall` и `policy rollback all`.

## Exclusive routes

`ensure-config`, `ensure-config-first-install`, `incident-init`,
`bootstrap-pam-password-slots`, `initialize-journal`, `complete-install`,
`incident-pam-alt attach/detach` и `pam-alt-pwhistory prepare` используют тот же
неблокирующий daemon.lock, что daemon startup. Installing допускает только
фиксированный installation allowlist с повторной проверкой состояния после lock.
Остальные exclusive routes требуют Installed. Unknown command/action отвергается
до dispatch. В UNINSTALLING обычная maintenance mutation не разрешена.

Infrastructure-only `fic-package-infrastructure` имеет ровно три операции:
`prepare-install`, `remove`, `prove-remove`. Он не загружает MutationJournal,
не применяет политики, не восстанавливает их значения и не выполняет произвольные
команды. Его writer/PAM proofs и durable publication выполняются под daemon.lock;
клиентские prepare/rollback запросы предшествуют получению этого lock, поскольку
работающий daemon удерживает его весь свой lifecycle.

## Read-only and resource serialization

`check-config`, `check-persistent`, `wait-daemon`, `incident-pam-verify`,
`incident-pam-prove-detached`, `validate-pam-slots-before-attach` и ALT topology
`status` не получают exclusive daemon admission. Они не инициализируют journal,
не принимают ownership и не выполняют policy release. `check-persistent` проверяет
конфигурацию, journal/witness и incident authority отдельным read-only snapshot.

Trust-sync сохраняет hash-store lock и проверяет Installed повторно внутри него.
Installation trust-sync допускается только при Installing под daemon.lock.
Daemon prepare-uninstall использует тот же hash-store barrier. Prelogin activation
также держит этот barrier и требует Installed; deactivation вызывается helper под
его уже полученным barrier. Подмена state после отдельного read не является
разрешением на mutation.

`fic-dick initialize-db` допускается при Installing; после получения существующего
DB resource lock повторяет проверку Installing. Installation completion использует
проверку той же БД под этим resource lock перед публикацией Installed.

## Limits

Нет общей гарантии исключения произвольного privileged legacy/manual executable.
Census отказывает при обнаруженных FIC identities/неидентифицируемых writers и не
убивает чужие процессы. Совместимость произвольных старых development scriptlets
не заявляется. Package mocks/static checks не являются native lifecycle proof;
проверенные платформы и незавершённые проверки перечислены в HANDOFF.
