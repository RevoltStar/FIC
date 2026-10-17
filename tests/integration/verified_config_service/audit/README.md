# Read-only OpenSSH compatibility audit

Результаты и ограничения: [native audit](../../../../docs/verified-config-native-compatibility-audit.md).

Сборка **внутри соответствующей native userspace**, с уже установленными build
зависимостями FIC и libsystemd development headers:

```sh
cmake -S tests/integration/verified_config_service/audit -B build-audit \
  -DFIC_TARGET_PLATFORM=debian-12
cmake --build build-audit --target verified_config_readonly_audit -j2
./build-audit/verified_config_readonly_audit > checks.json
```

Профили: `debian-12`, `debian-13`, `ubuntu-24.04`, `ubuntu-26.04`, `alt-p11`.
Запуск от root нужен для `/run/systemd/private` и чтения process root. Probe
не устанавливает FIC и не регистрирует hashes; отсутствие trust store остаётся
`NOT_TESTED`. Его exit 0 означает завершённый сбор результатов, **не** успешный
preflight. В JSON надо проверять каждое условие и оставшиеся `NOT_TESTED`.

Используются настоящие `readLaunchContract`, `validateLaunchContract`,
`requireSafePublicationParent`, `openAbsolute/readTree/verifyTree`,
`SshConfigAudit`, `trustedSshInput`. Запуск active preflight целиком намеренно
не выполняется: конструктор требует deployed trust, а дальнейшая activation
изменяла бы состояние. Дополнительные unit checks явно помечены как
`systemctl show + code-derived constraint`. Они не заменяют typed reader.

`systemctl show` скрывает credentials как `[unprintable]`, даже пустые; это
`NOT_TESTED`, не `UNSUPPORTED`. Где typed reader прошёл, `typed.launch.*Credential`
проверяет фактическую пустоту без вывода значений. `typed_properties` содержит
только signature/empty, а не данные. При отказе reader остальные проверки
продолжаются. Для inactive unit возможен `GetUnit: No such file or directory`
из-за отсутствия удерживающего loaded unit; это наблюдаемый отказ конкретного
снимка, не доказательство несовместимости D-Bus всей платформы.

`collect.py CONTAINER` читает metadata уже работающего Docker-контейнера:

```sh
python3 tests/integration/verified_config_service/audit/collect.py SUBJECT > metadata.json
```

Ни probe, ни collector не вызывают activate, mount/umount, restart/reload,
start/stop, daemon-reload, enrollment; не пишут configuration/unit/trust files.
Collector не создаёт контейнеры. Preparation/установка пакетов/первичная загрузка
должны происходить отдельно в disposable среде. Не запускайте полный native
activator runner ради этого аудита: он выполняет state-changing fixture tests.

Manifest строится по **наблюдаемым** файлам только для проверки формы запроса
и ограничений файловой системы. Это не trusted policy reference. Include graph
переиспользует FIC parser и консервативно обходит Include независимо от Match;
не доказывает полноту будущих конфигураций или эквивалентность всех синтаксических
возможностей OpenSSH. Не читаются private keys/credential values.
