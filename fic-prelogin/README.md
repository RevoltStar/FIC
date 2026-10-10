# FIC Pre-Login Gate

Опциональный экран перед штатным Display Manager. Он не аутентифицирует
пользователей, не применяет политики и не меняет Incident Response/PAM.

## Systemd lifecycle

Пакет устанавливает `/opt/fic/bin/fic-prelogin`,
`/opt/fic/bin/fic-prelogin-integration` и `fic-prelogin.service` в системном unit
каталоге (`/lib/systemd/system` для DEB, `/usr/lib/systemd/system` для ALT RPM).
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

## Qt EGLFS/KMS frontend

Root broker остаётся `/opt/fic/bin/fic-prelogin`; графический executable —
`/usr/libexec/fic/fic-prelogin-frontend`, системный аккаунт `fic-prelogin`
(`nologin`, `/nonexistent`). Frontend получает только private inherited
SOCK_SEQPACKET fd, данные для отображения и три local actions. Administrative
socket не наследуется; `fic` group не передаётся. Broker ограничивает
supplementary groups `video`, `render`, `input` и `xgrp` на ALT p11; graphics account metadata
проверяется до запуска. Общий systemd cgroup и parent-death signal ограничивают
lifetime renderer; все прочие broker fd закрываются перед pinned `fexecve`.
Синхронный ProcessExecutor не используется для renderer, поскольку не поддерживает
asynchronous status/action channel и service-length cleanup lifecycle.
Broker сохраняет `CAP_KILL` для завершения renderer с другим UID; ошибка
сигнала или превышение срока ожидания не допускают успешного handoff.

Используется **системный Qt6 Widgets**, `QT_QPA_PLATFORM=eglfs`,
`QT_QPA_EGLFS_INTEGRATION=eglfs_kms`. Используются стиль Fusion и программный
курсор, без desktop style helpers и зависимости от аппаратного DRM cursor.
Qt/loader environment очищается; plugin
search ограничен compile-time системным каталогом с root-owned/non-writable
parents и проверкой EGLFS/KMS plugin files. Bundled `fic-gui` runtime не
используется. Package dependencies вычисляются из actual ELF и владельцев
обоих plugins, поэтому наличие `qtbase` само по себе не считается достаточным.
Qt остаётся отдельным shared runtime дистрибутива; новый bundled Qt не поставляется.
Базовый `fic` не получает новых Qt Widgets/EGLFS dependencies. При standalone
configure `-DFIC_PRELOGIN_GRAPHICS=OFF` controller/console не требуют Qt.

Seat0 primary DRM node выбирается через libsystemd sd-device enumeration;
предпочитается PCI boot VGA, иначе первый подходящий primary node. Устройство
другого seat не выбирается. KMS configuration передаётся Qt через sealed memfd,
без environment-selected file и без persistent/transient status files.
Qt работает без X11/Wayland/window manager. Единственное fullscreen окно
использует primary output; поддержка multi-GPU/multi-monitor не подтверждена.
Режим/severity с отсутствующим proof обозначаются в UI как неподтверждённые.
Длинная diagnostic прокручивается отдельно: manual/power buttons не исчезают.
Power confirmation имеет default «Нет»; пароля/root shell/user session нет.

После подтверждённого startup success и renderer-ready начинается видимый
пятисекундный отсчёт «Переход к системному DE через X секунд...». Он использует
monotonic clock; потеря readiness/renderer либо смена daemon PID сбрасывает
отсчёт. Перед auto-handoff статус проверяется повторно. Manual/power actions
не ждут таймер. Отсчёт отображается также в текстовом fallback.

Renderer-ready barrier удерживает auto-handoff до готовности QPA; manual action
остаётся независимым от daemon. При handoff broker прекращает polling,
передаёт quit, ждёт normal process exit/reap (не window-close acknowledgement),
восстанавливает display/keyboard/VT modes, termios и previous VT; доказывает, что в unit cgroup остался
только broker. Дополнительный process, nonzero exit или forced kill означает
failure, а не успешный handoff. Затем broker exit(0) освобождает pending DM job.
Закрытие процесса освобождает DRM/GBM/EGL/input fd; ожидание по времени не
используется как доказательство освобождения ресурсов.

Missing/untrusted plugin, отсутствие seat0 DRM или renderer crash дают
диагностику в journal и interactive text fallback на tty7 **после reap** и
восстановления terminal state. Enter/`handoff` остаётся локальным переходом;
Ctrl+Alt+F1 оставляет recovery TTY. Если восстановление/cleanup не доказаны,
unit завершается failure, DM не выдаётся ложный success. Stopped failed unit
можно деактивировать/удалить только после доказанного empty cgroup.

### Проверенная конфигурация и ограничения

Реальная graphics/systemd validation относится к disposable Debian12 VM,
virtio-gpu/seat0, Mesa LLVMpipe, system Qt6.4, LightDM/GTK greeter. Configure/build
и offscreen GUI tests других платформ не доказывают их GPU/DM E2E.
Startup состояния в VM задаёт guarded read-only fixture с production serializer;
systemd, Qt/KMS, logind, LightDM и PAM account probes — реальные. Это не E2E
реального применения всех политик daemon. Optional DEB lifecycle проверяется
с `--force-depends`: base daemon/PAM binaries staged отдельно, без `fic` dpkg
record; полный dependency/install lifecycle базового пакета этим не доказан.
Не заявляется универсальная поддержка hardware GPU, multi-seat или monitors.
Ручной handoff не делает недоказанный autologin безопасным: integration helper
проверяет installed controlled PAM account paths, а дополнительные нестандартные
login paths требуют отдельного proof. Root/external writers сохраняют residual
races между snapshot proof и последующим systemd/driver действием.
