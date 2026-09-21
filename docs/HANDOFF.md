# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `411870107ce3d0441b0004683f196c327a03263c`, изменения
  поверх него коммитом не зафиксированы.

## Current task

- Debian/Ubuntu packaging follow-up: recovery после failed `prerm remove` —
  early `postinst abort-remove` path, behavioral/regression тесты,
  real-systemd harness expectations, документация.

## Accepted architecture / invariants

- **prerm remove** (без изменений): `systemctl disable --now` всех FIC
  сервисов (best-effort) + bounded wait (10×1s/unit) + финальный строгий
  `systemctl is-active` proof БЕЗ `|| true`; если unit ещё active —
  diagnostic + `exit 1`, `pam-auth-update --remove` НЕ вызывается.
- **Новый `postinst abort-remove`** (пакет `fic`, генератор
  `write_system_integration_symlink_postinst`): early branch сразу после
  `set -e`, ДО triggered/configure logic. Контракт:
  - If `prerm remove` fails before PAM hook detach because a FIC PAM writer
    remains active, dpkg's `postinst abort-remove` path restores
    package-managed service enablement/runtime state without touching PAM
    hooks, PAM managed slots, mutation journal, or journal witness.
  - `abort-remove` is not a configure path.
  - systemd-only recovery: `daemon-reload` → enable fic/fic-device/notify +
    udev helper → start fic/fic-device/notify. `start` на active unit
    идемпотентен; stop/restart в abort-remove НЕ вызываются никогда.
  - Critical units: `fic.service`, `fic-device.service` — после recovery
    должны быть active+enabled, строгий `is-active` proof в конце;
    иначе `exit 1` с diagnostic. `fic-notify.service` и
    `fic_get_device_udev_info.service` — best-effort (прежняя optional
    семантика).
  - Никогда: pam-auth-update (любой вызов), neutralize/rewrite/repair
    slots, rollback/discard/mark/migrate journal/witness,
    ensure-config/check-config/check-db/trust-sync/
    validate-pam-slots-before-attach как «recovery».
  - Сам `dpkg --remove fic` остаётся non-zero; пакет возвращается в
    `install ok installed` (не half-configured).
- Normal `postinst configure` и `prerm remove` orderings не изменены.

## Completed

- `packaging/deb/build-fic-debian12-deb.sh` — early `abort-remove` branch в
  generated `fic` postinst.
- `tests/integration/packaging/PamPackagingChecks.py`:
  - статические проверки abort-remove блока (позиция до stop-loop и
    configure branch, обязательные ops, запрет pam-auth-update/
    maintenance/stop/restart/disable);
  - behavioral Test A: полный generated postinst `abort-remove` на
    fakes-only PATH — rc 0, только systemctl recovery ops, ни одной
    configure-path команды;
  - behavioral Test B: live fic.service (active+disabled, stop/restart
    всегда fail у fake) → rc 0, порядок daemon-reload → enable → start,
    is-active proof, финальное active+enabled состояние всех units;
  - behavioral Test C: start критичного unit невозможен → rc≠0, unit
    в diagnostic.
- `fic_pam_systemd_ipc_lifecycle_v4.py` refusal scenario: после failed
  remove дополнительно проверяет fic/fic-device/fic-notify active+enabled,
  slots byte-for-byte, journal/witness sha256, `install ok installed`,
  cleanup RefuseManualStop drop-in + `fic --maintenance wait-daemon 10`.
- Документация: `docs/pam-owned-faillock-slots.md` (новый раздел
  «Failed removal recovery (postinst abort-remove)» + invariants),
  `packaging/deb/README.md`.

## Changed areas

- `packaging/deb/build-fic-debian12-deb.sh`, `packaging/deb/README.md`;
- `tests/integration/packaging/PamPackagingChecks.py`;
- `fic_pam_systemd_ipc_lifecycle_v4.py` (repo root);
- `docs/pam-owned-faillock-slots.md`, `docs/HANDOFF.md`.

## Validation

- `python3 tests/integration/packaging/PamPackagingChecks.py .` — passed
  (включая новые A/B/C behavioral abort-remove тесты).
- `bash -n packaging/deb/build-fic-debian12-deb.sh` — успешно.
- `ctest -R pam_packaging_static_checks` (build-check) — passed.
- `git diff --check` — успешно.
- Real-systemd harness `fic_pam_systemd_ipc_lifecycle_v4.py` (запуск через
  `sudo -n python3 …`, HEAD == REFERENCE_COMMIT `4118701…`):
  - debian12 (`/tmp/fic-abort-removal-debian12-sudo.json`): PASS;
  - debian13, ubuntu2404, ubuntu2604 (`/tmp/fic-abort-removal-rest.json`):
    PASS;
  - оба сценария на каждой цели: `real_systemd_remove_reinstall` (реальный
    daemon IPC state пережил remove/reinstall; stop-before-detach
    наблюдался) и `prerm_refuses_detach_while_fic_service_alive` (реальный
    systemd держал fic.service; prerm failed; abort-remove восстановил
    сервисы и состояние пакета; hooks/slots/journal не тронуты).

## Remaining

- Задача завершена. Изменения не закоммичены (поверх `4118701…`).
- Infra-заметка (не блокер): в этой среде `docker` в интерактивном shell —
  alias на rootless podman; системный docker socket требует root. Harness
  (`subprocess ["docker",…]`) запускать как `sudo -n python3
  fic_pam_systemd_ipc_lifecycle_v4.py …`.
