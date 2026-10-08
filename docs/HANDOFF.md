# FIC handoff

## Current base

* Branch `main`; task base `943b34b580b6a93e608b98d75f1bd8914a2e3353`.

## Current task

* Model A (session-derived containment targets) — реализовано.

## Accepted architecture / invariants

* **Model A:** цели containment выбираются только по доказанным обычным logind login-сессиям (`Class=user/user-early/user-light/user-early-light` + NSS identity proof + не root/recovery). Login shell, UID-диапазоны, имя пользователя и `/etc/passwd` НЕ участвуют в выборе цели. `Service` больше не производится классификатором.
* `IncidentController` owns severity/mode decisions; `LogindSessionContainmentBackend` only inventories, acts, and verifies. OFF/PASSIVE do not mutate sessions. Network quarantine remains the existing null backend.
* **Durable target store** `incident_session_targets` (рядом с lockstatus, root-owned 0640, atomic replace + fsync файла и каталога, версионированный JSON: `boot_id`, `incident_generation`, targets с evidence). Инвариант: **сначала durable регистрация цели, затем разрушающее действие**; неуспешная регистрация удерживает `TerminateSession` и даёт `DEGRADED`.
* Списки целей: session-level — обычные login-сессии текущего инцидента; user-runtime (ISOLATE) — **только** pending-цели из store. `ListUsers` — не источник новых целей, только механизм действия/верификации выбранных UID через `lookupProvenUser(uid, expectedName)`.
* Переживает: повторный `reconcile()`, частичный отказ `TerminateSession`/`TerminateUser`, рестарт FIC (store), эскалацию STANDARD→HARD→ISOLATE. Проверенный kernel reboot (смена `boot_id`) разрешает runtime-обязательства предыдущей загрузки; soft-reboot с тем же `boot_id` их сохраняет.
* `incident_generation` инкрементируется при новом инциденте (raise с proven UNLOCKED) и после административного clear: цели старого инцидента не могут сработать в новом. Два persistent-объекта (lockstatus + store) не заменяются атомарно вместе; промежуточные состояния разрешены в безопасную сторону (следующий raise заменяет store целиком).
* Недоказуемый (повреждённый) store → `DEGRADED`, никаких unsafe-действий и никогда не пустой успех. UID reuse (UID теперь другой аккаунт) → отказ + `DEGRADED`.
* Root, configured recovery-group members, greeter/service и unproven identities никогда не являются целями. Unknown class делает inventory недоказанным.
* Logind actions are pinned to its unique D-Bus owner, with immediate identity recheck. The narrow race between recheck and terminate was accepted for explicit documentation.

## Completed

* Production `IncidentSessionTargetStore` (SecureStateFile + AtomicFileWriter, fault-injection seams унаследованы), controller registration-before-termination, ISOLATE через store, clear/new-incident generation protocol, `lookupProvenUser` в backend API.
* Удалена shell-based классификация (`Service` по `nologin/false/true`); Model A в `classifyProductionContainmentIdentity`.
* `tests/fic/incident/ModelAContainmentTests.cpp` — production-to-production сценарии R1–R8 (partial failure+reconcile, HARD→ISOLATE escalation, restart recovery, corrupt store, UID reuse, clear isolation, root/recovery/lingering-only).
* Обновлены IncidentControllerTests/LogindSessionContainmentBackendTests под Model A.

## Changed areas

* `fic/src/incident/IncidentSessionTargetStore.{h,cpp}` (новый), `fic/src/incident/IncidentController.{h,cpp}`, `fic/src/session/{LogindSessionContainmentBackend,SessionContainmentBackend}.h`, `fic/src/session/LogindSessionContainmentBackend.cpp`, `fic/src/main.cpp` (wiring через 3-arg ctor), тесты, `fic/README.md`.

## Validation

* Fresh full build OK; полный CTest **143/143 passed** (включая новый `model_a_containment_tests`).
* `mutation_journal_tests` под UID 1000 — PASS.
* `git diff --check` passed.
* RED-before: старая shell-классификация противоречила R6/R7 сценарием (lingering-only service был бы целью через ListUsers; genuine login session service — нет); отсутствие store-привязки допускало потерю pending obligation после TerminateSession. Исполнительный RED прогон против base `4bf3a41` не выполнялся (production-код заменён); противоречия закреплены регрессиями Model A suite.

## Remaining

* No live host session mutation or real desktop/session E2E has been performed. Verify runtime D-Bus behavior in disposable systemd staging before deployment; fake transport tests do not prove real DE lock behavior.
* Network quarantine остаётся `NullIncidentNetworkBackend` — незавершённая часть ISOLATE.
* Cross-distro targeted builds (Debian 12/13, Ubuntu 24.04, ALT p11) для Model A не прогонялись в этой сессии; Ubuntu 26.04 по-прежнему без PAM dev headers.
