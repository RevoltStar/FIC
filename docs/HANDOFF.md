# FIC: передача контекста

## Current base

- Ветка `main`. Baseline: `bcb496f0d6a3700b78f3e6df05895cb31039b37f`
  ("Follow-up к последнему коммиту №3"; Step 5B + remove-side follow-ups
  закоммичены).

## Current task

- **Step 5C (install-time attach password hooks) — ЗАБЛОКИРОВАН failed
  architecture gate. Production реализация НЕ начата и НЕ должна
  начинаться до topology-решения** (STOP по контракту gate).
- Реализован и оставлен в репозитории reusable gate harness:
  `tests/integration/packaging/PamArchitectureGate.sh` (запуск в disposable
  podman-контейнере; Docker daemon на хосте недоступен, podman работает).

## Architecture gate verdict (Debian 12 + Ubuntu 24.04, идентично)

Нейтральный attach password hook profiles ЛОМАЕТ штатный путь смены пароля
на системах без внешнего token producer:

```text
baseline (unix-only)                          -> chpasswd OK
history alone   (Q0=0/H0=1, split stack)      -> chpasswd FAIL
quality+history (Q0=1/H0=1, Step 5C target)   -> chpasswd FAIL
detach (baseline restored byte-exact)         -> chpasswd OK
```

Probe control: dangling include target проваливает chpasswd — проба
чувствительна к топологии (false negative исключён).

Причина (изолирована чистыми экспериментами, `pam-auth-update` — Perl,
`lines_for_module_and_type`):

1. `Password-Initial` вариант профиля используется ТОЛЬКО для модуля на
   modpos 0 Primary блока. Debian/Ubuntu `unix` профиль:
   Password-Initial = producer (`pam_unix.so obscure yescrypt`, без
   use_authtok, сам спрашивает и выставляет токен), Password = consumer
   (`use_authtok try_first_pass`, НИКОГДА не спрашивает). Любой FIC
   password профиль с priority > 256 (1024/1023) вытесняет unix с modpos 0
   → unix переключается в consumer-вариант → в стеке нет producer'а →
   `pam_chauthtok` fails ("Authentication token manipulation error").
   Воспроизводится БЕЗ FIC: ручное добавление `use_authtok try_first_pass`
   в stock unix-строку ломает chpasswd так же.
2. Вариант с priority < 256 (hooks после unix) ломается иначе: comment-only
   slot включает 0 PAM handlers, но сгенерированный `[success=N]` прыжок
   считает include-строки как модули → overshoot past `pam_permit` →
   "Permission denied".
3. Контрэксперимент: priority < 256 + структурные нейтральные слоты
   (faillock-стиль: ровно одно инертное правило, напр.
   `password optional pam_deny.so`) — chpasswd OK в обоих состояниях. НО
   это ломает Step 7: quality enforcement требует позицию ДО pam_unix
   (смена пароля), а low-priority include всегда после. Требуется
   архитектурное решение (см. Remaining).
4. Faillock hooks это не задевает: их нейтральные слоты уже структурные
   (`<facility> optional pam_deny.so`) и auth/account стеки не имеют
   producer/consumer переключения unix-профиля.

## Real pam-auth-update grammar (подтверждено gate, Debian 12 + Ubuntu 24.04)

- Include-строки package-профилей имеют TRAILING SPACE
  (`password\tinclude<spaces>fic-password-quality `) — anchored `$`-proofs
  без `[[:space:]]*$` никогда не сходятся с реальной генерацией.
- `fic-password-history-initial` include генерируется ТОЛЬКО в
  history-alone split-состоянии. В both-selected состоянии (Step 5C target)
  генерируются только НОРМАЛЬНЫЕ includes обоих hooks; initial include
  ОТСУТСТВУЕТ.
- Следствие — LATENT ДЕФЕКТ Step 5B (не чинить в отрыве от topology-решения):
  `fic_prove_password_hook_state_restored` в prerm требует оба history
  includes и не допускает trailing whitespace → на реальной системе prerm
  recovery proof `(1,1)`/`(d,1)` никогда не сойдётся (fail closed, всегда).
  Fake в `PamPackagingChecks.py` моделирует dual-include без trailing
  space — расходится с реальностью в тех же пунктах.

## Ownership boundary (accepted, неизменно)

```text
package owns infrastructure/existence  (hook profiles + slot conffiles)
runtime policy + journal own managed state
pam-auth-update owns generated common-* files
```

`PamPolicySupport::ReadOnly` не поднимается; `enable_password_quality` /
`enable_password_history` не активируются (Step 7). Journal/rollback не
изменяются. Прямые правки `common-*` запрещены — writer только
pam-auth-update.

## Step 5B (committed, bcb496f) — коротко

- Bootstrap: `fic --maintenance bootstrap-pam-password-slots`
  (existence-only, exclusive durable create, canonical neutral bytes,
  no journal/witness).
- PreAttach: `fic --maintenance validate-pam-slots-before-attach`
  (faillock + password PreAttach verdicts, read-only, fail closed).
- postinst configure: bootstrap -> validate -> faillock attach (Step 5A).
  Password attach отсутствует (Step 5C заблокирован).
- prerm remove: snapshot Q0/H0 -> remove всех profiles -> proof (0,0) ->
  faillock restore -> selection-preserving fail-fast password restore
  (per-profile enable, immediate proofs, финальный full-state proof).
- Валидация Step 5B: `PamPackagingChecks.py`, `ctest -R pam_packaging`,
  artifact-проверка prerm. Контракт тестов опирается на fake-модель
  grammar, которая частично расходится с реальной (см. выше) — при переделке
  payload переделать fake/proofs вместе.

## Changed areas (этот шаг, uncommitted)

- `tests/integration/packaging/PamArchitectureGate.sh` (новый) — reusable
  gate harness + зафиксированный STATUS verdict в header.
- `docs/HANDOFF.md` (этот файл).
- Production code НЕ изменялся.

## Validation

- `sh -n tests/integration/packaging/PamArchitectureGate.sh` — PASS.
- Gate прогнан в podman на `debian:12` и `ubuntu:24.04`: детерминированный
  FAIL (см. verdict), все grammar-проверки PASS, probe control PASS,
  detach/restore/idempotence PASS.
- Изолированные эксперименты в контейнерах: use_authtok-воспроизведение,
  low-priority + comment-only slots, low-priority + структурные slots
  (chpasswd OK), `-remove` unselected профиля (rc=0, no-op).
- Build/CTest в этом шаге НЕ запускались (production code не менялся).
- Docker daemon недоступен на хосте; apt внутри контейнеров debian:12 /
  ubuntu:24.04 сломан (зеркала) — libpam-pwquality (внешний producer case)
  установить не удалось, docker-сборка пакета не выполнялась.

## Remaining

1. АРХИТЕКТУРНОЕ РЕШЕНИЕ (владелец проекта) по password payload topology:
   - вариант A: структурные нейтральные слоты (faillock-стиль) + priority
     < 256 — Step 5C безопасен, но Step 7 quality enforcement требует
     нового механизма позиции (runtime-активируемый producer-профиль или
     иное);
   - вариант B: сохранить priority > 256 и найти инертный token producer
     для нейтрального окна (stock-модуля нет);
   - вариант C: перенос attach из postinst в момент первой policy
     activation.
2. После решения: переделать payload (+ возможно canonical neutral bytes в
   `PamManagedPasswordSlots`), прогнать gate повторно, и только потом
   реализовывать Step 5C (attach + compensation + attached validator CLI +
   tests).
3. Починить latent Step 5B proof-grammar дефекты (trailing whitespace,
   initial-include ожидание) вместе с topology-решением; синхронно fake.
4. Step 6: Debian 12 ModuleArguments option writer. Step 7: runtime
   activation + lifting ReadOnly.
5. Среда: docker daemon не запущен; apt-зеркала в контейнерах частично
   битые (Dockerfile-сборка пакета падает на qt6-*/xauth/xvfb).
6. Baseline failure `passwdqc_config_file_tests` — вне scope.
7. Не запускать параллельно `/tmp`-конфликтующие test-наборы.
