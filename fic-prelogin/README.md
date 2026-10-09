# FIC Pre-Login Gate

Опциональный экран перед штатным Display Manager. Он не аутентифицирует
пользователей, не применяет политики и не меняет Incident Response/PAM.

## Systemd lifecycle

Пакет устанавливает `/opt/fic/bin/fic-prelogin`,
`/opt/fic/bin/fic-prelogin-integration` и `/lib/systemd/system/fic-prelogin.service`.
Checked helper устанавливает только собственный
`/etc/systemd/system/display-manager.service.d/50-fic-prelogin.conf`:

```ini
[Unit]
Requires=fic-prelogin.service
After=fic-prelogin.service
```

Gate — `Type=oneshot`, `RemainAfterExit=yes`, `Before=display-manager.service`;
`Wants=fic.service` без `After/Requires=fic.service`. DM и gate участвуют в одной
transaction. Выход gate с ошибкой не разрешает DM; успешный выход освобождает
ожидающий start job. Обычный restart DM не запускает экран снова.
Никакого прямого запуска DM из gate нет.

Activation проверяет selected alias (GDM/SDDM/LightDM), production PAM account
proof, effective graph и `systemd-analyze verify`. Vendor units, alias symlink
и administrator drop-ins не заменяются. При отсутствии DM пакет остаётся
неактивным. Offline installation требует явного `fic-prelogin-integration
activate` после загрузки. Работающий DM при установке не останавливается.

Deactivation сначала завершает работающий gate с cleanup, затем удаляет только
точно совпадающий managed drop-in и доказывает отсутствие его dependencies.
Уже завершённый gate останавливается после detach, чтобы не остановить DM.
Чужой/изменённый drop-in или administrator dependency вызывает диагностируемый
отказ. Offline removal удаляет только доказанный managed file; отсутствие
live bus не используется как fallback на работающей системе. При ошибке helper
package operation завершается с ошибкой. Recovery: отдельный TTY, локальный root,
`fic-prelogin-integration deactivate`; затем штатный DM запускает администратор.

## Status and handoff

До создания IPC socket systemd `MainPID`, `ActiveState`, `SubState`, `StatusText`
используются только для отображения progress. `READY=1` не доказывает apply.
Read-only `prelogin_status` использует administrative socket с проверкой root
peer UID, kernel peer PID, systemd MainPID при доступном observer, bounded
transport и exact typed schema. Environment не меняет production endpoint.

Общие 10 полей `access_gate_status`: `api_version`, `ok`, `message`,
`daemon_state`, `response_mode`, `response_mode_proven`, `severity`,
`persistent_state_proven`, `persistent_provenance`, `ordinary_login_allowed`.
`prelogin_status` добавляет ровно 7 полей: `startup_apply_started`,
`startup_apply_completed`, `startup_apply_ok`, `startup_lifecycle_completed`,
`diagnostic`, `boot_id`, `daemon_pid`. API version берётся из shared IPC contract.
JSON duplicate keys, неизвестные поля, типы и несогласованные значения отвергаются.

First apply result хранится только в памяти конкретного daemon instance;
periodic/admin apply его не перезаписывает. Boot ID проверяется с текущим kernel.
Auto-handoff требует успешного first apply, завершённого startup lifecycle,
доказанного response mode и READY/ordinary-login contract. Ошибка first apply,
недоступный daemon и недоказанный status никогда не означают успех.

Ручной переход доступен в любом состоянии, включая ACTIVE/ISOLATE и отсутствие
daemon. Он освобождает display resources и завершает gate, не меняя severity,
mode, lockstatus или PAM. В ACTIVE последующий ordinary login независимо
разрешает/запрещает `pam_fic_access.so`; OFF/PASSIVE сохраняют нейтральную
семантику. Recovery exemptions сохраняются. Autologin поддерживается лишь при
доказанном прохождении контролируемого account stack; имя DM само по себе
такого доказательства не даёт.

Headless вариант использует отдельный tty7; Enter/`handoff`, `reboot`, `poweroff`.
Power actions — только logind Reboot/PowerOff по system D-Bus, после cleanup;
произвольных команд и shell нет. SIGTERM/fatal error не выдаёт successful handoff.
TTY1 и другие recovery TTY не заменяются.

## Validation

Unit/transport tests: `prelogin_controller_tests`, `incident_access_client_tests`.
Generated package scripts: `prelogin_package_lifecycle_tests`.
Systemd/DRM проверки выполняются только в disposable VM. Контейнерная сборка
и offscreen tests не доказывают корректность DRM handoff или конкретного GPU.
