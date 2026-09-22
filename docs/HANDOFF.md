# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `d47c9e0ed1bedae1227a176d46deaa17a242b965`, рабочие
  изменения поверх него (не закоммичены): hardening follow-up пруфа
  permanent PAM hooks.

## Current task

- Hardening follow-up Debian/Ubuntu PAM lifecycle: ужесточён
  `fic_prove_permanent_hooks_attached()` (exact `Module:` selection в
  правильном facility-файле + anchored active include rule в generated
  common-*), добавлены negative/positive proof-тесты и consumer-path
  тесты (prerm recovery, postinst abort-remove). State machine removal/
  recovery НЕ изменена.

## Accepted architecture / invariants

- **State model пруфа** (`fic_prove_permanent_hooks_attached()`,
  генерируется builder-функцией `write_pam_hook_proof_function` и вставляется
  в ОБА скрипта — prerm и postinst; строго read-only):
  - selection: exact full-line `^Module: <profile>$` в ПРАВИЛЬНОМ
    facility state file — `/var/lib/pam/auth` для preauth/authfail/authsucc
    hooks, `/var/lib/pam/account` для account hook; запись в другом
    facility, внутри другой строки или prefix/suffix collision не
    доказывают selection;
  - physical attachment: anchored full PAM rule
    `^auth[[:space:]]+include[[:space:]]+<target>$` в generated
    `common-auth` (`^account ... include ... fic-faillock-account$` в
    `common-account`); комментарии, wrong facility, не-include control
    words, prefix/suffix targets и посторонние упоминания не доказывают
    attachment;
  - никогда не вызывает `pam-auth-update` и не мутирует PAM state, slots,
    journal, witness (регрессионно проверяется digest-тестом и статикой).
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
    sandbox), `canonical_include` (канонический include с facility),
    `write_attached_pam_state`/`read_pam_state`/`pam_state_digest`,
    stateful fake `pam-auth-update` (Module: блоки, регенерация common-*
    с facility-префиксом, инъекции remove-fail/partial/enable-fail +
    `FAKE_PAU_MALFORMED`=`commented`/`wrong-facility`);
  - **proof unit tests** (`proof_unit_tests`): сгенерированный пруф
    исполняется против sandbox-состояний — PASS на canonical topology
    (tab- и space-варианты whitespace), FAIL на: commented include,
    wrong facility include, target suffix collision, mere text occurrence,
    non-include control word (`optional`), Module: запись в wrong
    facility file, Module: suffix collision, отсутствующая Module:
    запись; digest-тест доказывает read-only пруфа;
  - статика: тело пруфа должно содержать exact `^Module: ...$` grep-и в
    правильных facility файлах и anchored include grep-и; запрещены
    слабые формы (`*"Module: $fic_hook"*`, `fic_selected=`, substring
    `grep -q`, `session-noninteractive`) и любые mutators;
    prerm recovery (только 4 hooks, запрет legacy, diagnostics, пруф,
    отсутствие fic-команд), abort-remove guard + strict notify;
  - behavioral prerm: A (detach fail, state untouched), B (partial detach →
    full restore), C (recovery fail + intact), D (partial + recovery fail →
    NOT proven restored), E (recovery enable «успешен», но regenerated
    физические строки malformed — commented/wrong-facility → NOT proven
    restored, rc≠0);
  - behavioral abort-remove: B расширен на fic-notify; D (notify
    enable/start/inactive failures → rc≠0); E (guard refusal на detached
    sandbox); F (корректные Module: записи + malformed commented/wrong-
    facility include → proof fail, ни enable ни start).
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

- `python3 tests/integration/packaging/PamPackagingChecks.py .` — passed
  (включая новые proof unit tests и consumer-path сценарии E/F).
- `bash -n packaging/deb/build-fic-debian12-deb.sh` — успешно;
  сгенерированные prerm/postinst тоже проверены `bash -n` (новый пруф
  присутствует в обоих).
- `ctest --test-dir build-check -R pam_packaging_static_checks` — 1/1
  passed.
- `git diff --check` — чисто.
- Локальный real-systemd harness НЕ перезапускался в этом follow-up:
  после ужесточения пруфа его инъекции/проверки не обновлялись и
  независимого real-systemd покрытия текущего пруфа нет. Committed
  coverage — behavioral-тесты `PamPackagingChecks.py` на fake
  pam-auth-update/systemctl; harness остаётся вне репозитория.

## Remaining

- Пользователь проверяет и коммитит рабочие изменения.
- Real-systemd harness требует обновления под ужесточённый пруф
  (канонический формат include с facility-префиксом), если независимое
  real-systemd покрытие понадобится снова.
- Infra: docker-контейнерам нужен прокси — в `~/.docker/config.json`
  добавлен клиентский `proxies` (`http://host.docker.internal:10809`) и
  **временно убран `credsStore`** (`docker-credential-desktop.exe`
  падал с `exec format error` в WSL и ломал даже `docker pull`;
  оригинал — `~/.docker/config.json.bak`). Прокси в этой сессии
  периодически отваливался — при повторных сбоях просто перезапускать
  прогон таргета. Восстановить `credsStore` из бэкапа, если нужен auth
  в приватные registry.
- Замечание: Half-Configured после guard refusal — осознанное fail-closed
  решение, зафиксировано в `docs/pam-owned-faillock-slots.md`.
