# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `6c9f43b306607342c22d132e2a211193ba53b442`
  (коммит «packaging(deb): recover Debian prerm PAM detach failures locally
  and prove permanent hook state»), рабочих изменений поверх него нет —
  кроме локального (git-ignored) harness-файла в корне.

## Current task

- Debian/Ubuntu packaging: сделать PAM detach при `prerm remove` локально
  восстанавливаемым (restore + proof permanent hook infrastructure при
  сбое), сохранить `postinst abort-remove` systemd-only, унифицировать
  семантику `fic-notify.service`, добавить behavioral-тесты. Задача
  завершена; ожидается завершение real-systemd прогона (см. Validation).

## Accepted architecture / invariants

- **State model пруфа** (`fic_prove_permanent_hooks_attached()`,
  генерируется builder-функцией `write_pam_hook_proof_function` и вставляется
  в ОБА скрипта — prerm и postinst): стандартное состояние
  `pam-auth-update` — файлы
  `/var/lib/pam/{auth,account,password,session,session-noninteractive}`
  содержат блоки `Module: <profile>` для всех четырёх permanent hooks,
  сгенерированный `/etc/pam.d/common-auth` упоминает
  `fic-faillock-{preauth,authfail,authsucc}`, `common-account` —
  `fic-faillock-account`. Строго read-only: никогда не вызывает
  `pam-auth-update`, не мутирует PAM state, slots, journal, witness.
- **prerm remove (Phase B recovery)**: `pam-auth-update --package --remove
  <10 profiles>` — failure-guarded (`if !`). При сбое: recovery
  `pam-auth-update --enable` ровно 4 permanent hooks (single `--enable`
  достаточен: re-select + regenerate; `--package` перед ним не нужен),
  затем пруф. Если `--enable` failed, но пруф проходит → «proven still
  attached»; если `--enable` failed И пруф failed (partial detach) →
  «NOT proven restored», partial state не трогается. Во всех случаях
  `exit 1` (removal failed).
- **prerm recovery восстанавливает ТОЛЬКО 4 permanent hooks**, никогда не
  legacy policy-owned selector profiles (fic-faillock-notify,
  fic-faillock-preauth-required, fic-faillock-authsucc, fic-pwquality,
  fic-pwhistory). prerm никогда не трогает slots/journal/witness и не
  запускает FIC-команды.
- **postinst abort-remove**: прежний контракт (early branch, не configure
  path, stop/restart никогда) плюс:
  - read-only guard `fic_prove_permanent_hooks_attached` ПЕРЕД любым
    действием: при непройденном пруфе отказывается перезапускать writers
    (`exit 1`, diagnostic «not proven attached»), пакет остаётся в dpkg
    error state (Half-Configured) для ручного восстановления. Без
    маркерных файлов: пруф stateless и покрывает даже crash между prerm и
    abort-remove. Guard добавлен потому, что dpkg вызывает abort-remove
    после ЛЮБОГО failed `prerm remove`, без указания причины (Debian
    Policy §6.8: abort-remove успешен → Installed; failed → Half-Configured).
  - `fic-notify.service` теперь strict (как в normal configure, где он
    mandatory: `systemctl enable --now` под `set -e`): strict enable,
    strict start, финальный `is-active` proof. udev helper остался
    best-effort.
- Нормальные `postinst configure` и prerm stop-before-detach ordering не
  изменены.

## Completed

- `packaging/deb/build-fic-debian12-deb.sh`: `write_pam_hook_proof_function`
  (единый source пруфа); prerm — detach под `if !` + recovery; postinst —
  guard + strict notify в abort-remove.
- `tests/integration/packaging/PamPackagingChecks.py`:
  - хелперы: `PERMANENT_HOOKS`/`LEGACY_POLICY_PROFILES`,
    `sandbox_pam_paths` (подстановка `/var/lib/pam`, `/etc/pam.d` в
    sandbox), `write_attached_pam_state`/`read_pam_state`, stateful fake
    `pam-auth-update` (Module: блоки, регенерация common-*, инъекции
    remove-fail/partial/enable-fail);
  - статика: prerm recovery (только 4 hooks, запрет legacy, diagnostics,
    пруф, отсутствие fic-команд), abort-remove guard + strict notify;
  - behavioral prerm: A (detach fail, state untouched), B (partial detach →
    full restore), C (recovery fail + intact), D (partial + recovery fail →
    NOT proven restored);
  - behavioral abort-remove: B расширен на fic-notify; D (notify
    enable/start/inactive failures → rc≠0); E (guard refusal на detached
    sandbox: rc≠0, ни start ни enable).
- `fic_pam_systemd_ipc_lifecycle_v4.py` (локальный harness, git-ignored):
  сценарий C `prerm_recovers_pam_after_partial_detach_failure` — wrapper над
  реальным `/usr/sbin/pam-auth-update`: первый `--package --remove`
  выполняет РЕАЛЬНУЮ partial мутацию (реальный `--remove` двух hooks) и
  падает; дальше реальные prerm recovery + proof + abort-remove; проверки
  diagnostics/wrapper log/services/attached/slots/journal/witness sha256/
  семантический статус пакета/`wait-daemon`. Семантическая проверка статуса
  (`${db:Status-Status}` == `installed`) в refusal и новом сценарии.
  REFERENCE_COMMIT = `6c9f43b306607342c22d132e2a211193ba53b442`.
- Документация: `docs/pam-owned-faillock-slots.md` (Phase B recovery,
  стандартный пруф, guard + strict notify, semantic Installed state),
  `packaging/deb/README.md` (кратко).

## Changed areas

- `packaging/deb/build-fic-debian12-deb.sh`, `packaging/deb/README.md`;
- `tests/integration/packaging/PamPackagingChecks.py`;
- `fic_pam_systemd_ipc_lifecycle_v4.py` (repo root, git-ignored);
- `docs/pam-owned-faillock-slots.md`, `docs/HANDOFF.md`.

## Validation

- `python3 tests/integration/packaging/PamPackagingChecks.py .` — passed.
- `bash -n packaging/deb/build-fic-debian12-deb.sh` — успешно;
  сгенерированные prerm/postinst тоже проверены `bash -n`.
- `ctest -R pam_packaging_static_checks` (свежая конфигурация в
  /tmp/fic-ctest-check) — 1/1 passed.
- `git diff --check` — чисто.
- Real-systemd harness (debian12, `--require-reference-commit`, HEAD ==
  REFERENCE_COMMIT `6c9f43b3…`, repo_head в
  `pam-systemd-ipc-lifecycle.json` совпадает с проверяемым commit) —
  **PASS, все 3 сценария**:
  - `real_systemd_remove_reinstall`: PASS;
  - `prerm_refuses_detach_while_fic_service_alive`: PASS;
  - `prerm_recovers_pam_after_partial_detach_failure` (новый): PASS —
    реальная partial мутация через реальный pam-auth-update → prerm
    восстановил+доказал hooks → abort-remove восстановил сервисы → пакет
    Installed, slots/journal/witness byte-for-byte, daemon healthy.
  - Логи: `/tmp/fic-v4-debian12-run3.log` (финальный зелёный),
    `/tmp/fic-v4-debian12-run2.log` (сценарий A упал по transient-сбою
    прокси в контейнере — не lifecycle-вердикт; B/C прошли),
    `/tmp/fic-v4-debian12.log` (первый прогон: A/B PASS, C упал только на
    некорректной проверке wrapper-лога в самом harness — исправлено).
- Real-systemd harness остальные цели (`--require-reference-commit`,
  repo_head == REFERENCE_COMMIT `6c9f43b3…` во всех JSON) — **все PASS**:
  - debian13: все 3 сценария PASS (`/tmp/fic-v4-rest.json`);
  - ubuntu2404: все 3 сценария PASS (`/tmp/fic-v4-rest.json`);
  - ubuntu2604: все 3 сценария PASS (`/tmp/fic-v4-u2604b.json`); два
    предыдущих прогона падали только на transient-сбоях прокси
    (`Unable to connect to host.docker.internal:10809`) при apt fetch
    внутри `docker build`/install — не lifecycle-вердикты.

## Remaining

- Infra: docker-контейнерам нужен прокси — в `~/.docker/config.json`
  добавлен клиентский `proxies` (`http://host.docker.internal:10809`) и
  **временно убран `credsStore`** (`docker-credential-desktop.exe`
  падал с `exec format error` в WSL и ломал даже `docker pull`;
  оригинал — `~/.docker/config.json.bak`). Прокси в этой сессии
  периодически отваливался — при повторных сбоях просто перезапускать
  прогон таргета. Восстановить `credsStore` из бэкапа, если нужен auth
  в приватные registry.
- Сгенерированный отчёт `pam-systemd-ipc-lifecycle.json` в корне репо —
  артефакт harness (по умолчанию туда пишет `--json`); не коммитить,
  при желании добавить в `.gitignore`.
- Замечание: Half-Configured после guard refusal — осознанное fail-closed
  решение, зафиксировано в `docs/pam-owned-faillock-slots.md`.
