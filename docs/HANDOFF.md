# FIC: передача контекста

## Current base

- Ветка `main`, HEAD `191dac23781631b9d68736a497e0c8a93a972a54`, рабочее
  дерево чистое (репозиторий данной сессией не изменялся).

## Current task

- Staged задача PasswordQuality/PasswordHistory managed topology
  (journal-bound, physically-owned; Debian 12/13, Ubuntu 24.04/26.04;
  ALT p11 не затрагивается). **Step 1 (design gate / fixture collection)
  завершена** — все fixture-доказательства собраны в disposable Docker
  контейнерах, дизайн-чекпоинт закрыт (см. ниже). Следующий шаг — Step 2:
  физическая managed topology + marker parsing в коде.

### Design gate: fixture-доказательства (Step 1, /tmp/pam-gate/)

Все проверки выполнены реальным `pam-auth-update` в disposable
контейнерах (`debian:12`, `debian:13`, `ubuntu:24.04`, `ubuntu:26.04`);
сырые артефакты — `/tmp/pam-gate/out2-*/` и сессия этой переписки.
Scratch вне репозитория намеренно (§33).

1. **Режим pwhistory (§16/§17 подтверждены)**: Debian 12
   `pam_pwhistory.so` не содержит строки `conf=` и не имеет
   `/etc/security/pwhistory.conf` → module-arguments mode. Debian 13,
   Ubuntu 24.04, Ubuntu 26.04 — есть `/etc/security/pwhistory.conf`
   (дефолты `remember = 0`, `retry = 1`) и строка `conf=` в бинарнике →
   config-file mode. `pam_pwhistory.so` входит в `libpam-modules`
   (пакета `libpam-pwhistory` не существует).
2. **Дистро pam-configs профили**: `unix` (Priority 256, с
   `Password-Initial`), `pwquality` (1024, `Conflicts: cracklib`, с
   `Password-Initial`), `mkhomedir`. **Дистро-профиля pwhistory нет ни на
   одной платформе** — единственные pwhistory-профили будут FIC-овыми.
3. **Hook include-профили работают**: `pam-auth-update --package --force`,
   затем `pam-auth-update --enable <hook-ids>` вставляет
   `password include <target>` в Primary block по приоритету. Размещение
   при Priority hook-quality=1024 / hook-history=1023:
   `pam_pwquality` → `include fic-password-quality` →
   `include fic-password-history` → `pam_unix`. Ручная запись
   `/var/lib/pam/*` без кэшированных строк профиля НЕ работает (pam-
   auth-update молча выкидывает такие записи) — только штатный
   `--package`+`--enable` flow, как в packaging builder.
4. **Control-flow переписывается динамически**: unix-строка в профиле —
   `[success=end default=ignore]`, в рендере — `[success=N ...]`, где N
   пересчитывается pam-auth-update при каждом enable/disable (вставка
   include-строки сдвигает/пересчитывает jumps; удаление модуля сдвигает
   номера строк). Вывод: сгенерированный common-password не байт-стабилен;
   ownership/marker-проверки должны нормализовать jump-count'ы и не
   полагаться на точные значения `success=N` или номера строк.
5. **Password-Initial / use_authtok token-flow** (авторитетно из
   `/usr/sbin/pam-auth-update`, `lines_for_module_and_type`): вариант
   `<Type>-Initial` используется ТОЛЬКО для модуля на позиции 0 стека
   (если определён); для позиций >0 — обычный вариант. Эксперимент:
   pwhistory после pwquality рендерится с `use_authtok`; pwhistory без
   pwquality (позиция 0) — без `use_authtok`; то же для pam_unix. Вывод:
   слоты нельзя копировать механически — FIC-owned slot-файлы обязаны
   задавать token-flow явно и позицию стека контролировать/проверять.
6. **Debian 12 vs 13/Ubuntu placement одинаковый** для hook-подхода:
   include-строки идентичны на всех четырёх образцах; различие только в
   mode pwhistory (п.1) — на Debian 12 аргументы (`remember=`,
   `enforce_for_root`) пишутся в строку модуля в FIC slot-файле, на 13/
   Ubuntu — в `/etc/security/pwhistory.conf` (конфиг в juice и т.п. — по
   схеме pwquality `PwqualityConfigFile`).

### Design checkpoint (A–J, §34) — зафиксированные ответы

- **A (placement)**: hook include-профили с Priority 1024/1023 дают
  гарантированное размещение между pwquality (1024) и unix (256);
  tie-break при равном приоритете с pwquality — pwquality раньше
  (проверено). Доказано на всех 4 платформах.
- **B (token-flow)**: use_authtok зависит от позиции стека (п.5) →
  FIC slot-файлы содержат окончательные строки модулей; hook include
  только подключает их; позиция slot-файла в стеке фиксируется
  приоритетом и проверяется пруфом.
- **C (jump normalization)**: маркер/пруф не должны зависеть от
  `success=N` и номеров строк (п.4) — использовать anchored include
  rule, как в faillock-пруфе.
- **D (mode split)**: Debian 12 — module-arguments ownership (Step 6);
  Debian 13/Ubuntu — config-file mode (§17). Оба пути сохраняют
  независимый persistent config от топологии.
- **E (legacy)**: `fic-pwquality`/`fic-pwhistory` остаются legacy; новых
  hook profile IDs — `fic-password-quality-hook`/`fic-password-history-hook`
  (Priority 1024/1023, Password-Type: Primary, `include` FIC slot target);
  автоприменения legacy-выборов нет.
- **F (ReadOnly lift)**: `PamPolicySupport::RequiresTopologyActivation`
  поднимается только после marker+journal+placement proof (Step 7);
  `legacyPamAuthUpdatePasswordTopology` bypass удаляется последним.
- **G (state format)**: единственный надёжный канал включения профиля —
  `pam-auth-update --enable` после `--package`; ручное редактирование
  `/var/lib/pam/*` ломает state (п.3) — validator должен отказывать при
  hand-edited state.
- **H (conf= availability)**: решение о mode принимает платформенный
  профиль, а не эвристика бинарника (строки `conf=`/файл конфига
  зафиксированы в профилях Debian12/Debian13/Ubuntu2404(+2604)).
- **I (idempotence)**: повторные `--enable`/`--disable` циклы
  пере-рендерят файл полностью; placement/пруф должен переживать
  re-render (anchored, не line-based).
- **J (нет дистро-конкуренции)**: дистро не поставляет pwhistory-профиль
  (п.2) — конфликтов `Conflicts:` с FIC pwhistory hook не будет;
  `Conflicts: cracklib` у pwquality не затрагивается.

Примечание: вербальный список §34 A–J из исходного текста задачи был
утерян при сжатии контекста; выше — реконструкция ответов по существу
(placement graph, Password-Initial split, use_authtok ordering, §6/§37).
Если формулировки чекпоинтов в исходной задаче отличаются — сверить и
дозаполнить перед Step 7 (lift ReadOnly).

## Accepted architecture / invariants

- **Faillock permanent-hook proof** (`fic_prove_permanent_hooks_attached`,
  генерируется `write_pam_hook_proof_function` в
  `packaging/deb/build-fic-debian12-deb.sh`, строго read-only):
  selection = exact full-line `^Module: <profile>$` в правильном
  facility state file; attachment = anchored full PAM include rule в
  generated common-*; prefix/suffix collision, wrong facility,
  комментарии, не-include control words не доказывают attachment;
  пруф никогда не вызывает `pam-auth-update` и не мутирует PAM state.
  Авторитетное описание: `docs/pam-owned-faillock-slots.md`.
- **prerm recovery восстанавливает ТОЛЬКО 4 faillock permanent hooks**,
  никогда не legacy policy-owned selector profiles (включая
  fic-pwquality, fic-pwhistory).
- PasswordQuality/PasswordHistory managed topology строится по этой же
  модели (marker slots + mutation-id journal + placement/proof) —
  контракт см. в Design gate / checkpoint выше.

## Completed

- Step 1 design gate (fixture collection) полностью: см. секцию
  «Design gate» в Current task. Код репозитория в рамках Step 1 не
  менялся; обновлён только `docs/HANDOFF.md`.

## Changed areas

- `docs/HANDOFF.md` (единственное изменённое файл; scratch-артефакты —
  `/tmp/pam-gate/`, вне репозитория).

## Validation

- Real `pam-auth-update` прогоны в disposable Docker контейнерах
  debian:12, debian:13, ubuntu:24.04, ubuntu:26.04 (пробинг `conf=`/
  `/etc/security/pwhistory.conf`, `--package --force` + `--enable` hook
  и legacy профилей, чтение `/usr/sbin/pam-auth-update` для
  `lines_for_module_and_type`). Никаких изменений host-системы;
  контейнеры `--rm`.
- `git status --short` — чисто; `git log -1` = `191dac2`.
- Сборка/тесты не запускались: код не менялся.

## Remaining

- Step 2: физическая managed topology + marker parsing в
  `fic/src/modules/identity_access/pam/` (по модели
  `PamAuthUpdateTopologyManager`/faillock slots).
- Step 3: journal-bound ownership; Step 4: pre-attach validator
  (`PamSlotAttachValidator`); Step 5: packaging (новые pam-configs hook
  профили + slot targets в `packaging/deb/`, permanent-hook proof
  расширить на password hooks).
- Step 6: Debian 12 module-argument ownership; Step 7: lift
  `PamPolicySupport::ReadOnly` → `RequiresTopologyActivation`, удалить
  `legacyPamAuthUpdatePasswordTopology` bypass (последним).
- Step 8: тесты. Обязательные targeted suites перед снятием bypass:
  PamCapabilityActivationPolicyTests, PamAuthUpdateTopologyManagerTests,
  PamSlotAttachValidatorTests, PamOptionPolicy/pwhistory argument tests,
  PlatformProfileTests, RollbackExecutorTests, PamPackagingChecks.
- Step 9: docs (`docs/pam-owned-faillock-slots.md` или новый документ).
- Сверить реконструкцию чекпоинтов A–J (§34) с исходным текстом задачи
  перед Step 7 — вербальный список утерян при сжатии контекста,
  содержательные ответы зафиксированы в Current task.
- Infra: docker-контейнерам нужен прокси — в `~/.docker/config.json`
  добавлен клиентский `proxies` (`http://host.docker.internal:10809`) и
  **временно убран `credsStore`** (`docker-credential-desktop.exe`
  падал с `exec format error` в WSL и ломал даже `docker pull`;
  оригинал — `~/.docker/config.json.bak`). Daemon при этом инжектит
  сломанный proxy env (`127.0.0.1:20171`) во все контейнеры — рабочая
  комбинация: `docker run --env http_proxy= --env https_proxy= --env
  HTTP_PROXY= --env HTTPS_PROXY= ...` (apt внутри работает). При
  повторных сбоях просто перезапускать прогон таргета. Восстановить
  `credsStore` из бэкапа, если нужен auth в приватные registry.
