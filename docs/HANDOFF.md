# FIC handoff

## Current base

* Branch `main`; follow-up based on `f910e50de867ff64be34d60c50d5ca9f4c20f068`.

## Current task

* Исправление ordinary FIREWALL rollback provenance при profile restoration; implementation и вся required validation завершены. Focused follow-up commit `Preserve FIREWALL rollback provenance across profile restoration`.

## Accepted architecture / invariants

* Unified FirewallCoordinator и IncidentController authority NORMAL/INCIDENT_QUARANTINE сохранены. Compiler, JSON schema, IPv4/IPv6 semantics, incident severity/state format и Model A не менялись.
* Все ordinary creations, включая direct apply, full/startup/periodic/exclusive reconcile и возврат из ISOLATE/OFF/PASSIVE, проходят общий physical execution boundary `FirewallBackend::applyEffective`.
* Ordered protocol: actual inspection + manifest proof → witness-aware durable journal proof → все missing ordinary Prepared → durable ownership intent → ONE checked nft batch → independent complete kernel proof → durable Prepared→Applied. Journal и manifest не являются одной файловой транзакцией.
* Existing Prepared разрешается на том же id после fresh proof, в том числе kernel no-op после crash. Applied no-op не переписывается; RollbackFailed authority/diagnostic сохраняется. Missing table с existing active record восстанавливается без duplicate. Preparation/ownership/apply/proof/partial commit failure не теряет unresolved provenance и не сообщает успех.
* Manifest-proven existing ordinary table без journal — provenance conflict; foreign/legacy objects не принимаются. Автоматической миграции/adoption нет.
* Production rollback использует explicit `removePolicy`: release только выбранной таблицы, без создания missing ordinary resources других policies/exclusive actions. Empty-rules обычный apply по-прежнему способен восстановить полный NORMAL profile.
* ISOLATE deferred apply не создаёт false Applied. Ordinary journal error не ослабляет quarantine; failed NORMAL restoration сохраняет durable UNLOCKED и сообщает DEGRADED. Empty NORMAL cleanup без ordinary creation не зависит от journal.

## Completed / changed areas

* `fic/src/modules/firewall/FirewallBackend.{h,cpp}`, `FirewallCoordinator.{h,cpp}`; production callback в `rollback/RollbackExecutor.cpp`.
* 20 focused provenance scenarios в `FirewallProvenanceTests.cpp`, shared fake nft fixture; реальный `rollbackPolicyBeforeDisable` и persistent restart/recovery. IncidentController clear/journal-failure integration regression.
* `tests/CMakeLists.txt`, rollback/profile test entry points; FIREWALL README, rollback docs и architecture diagram.

## Validation

* Executable RED-before на unchanged production `f910e50`: R1–R3/R5 отказ production disable из-за provenance; R4/R6–R10/R12 ожидаемые violations; R11 уже PASS. Log `/tmp/fic-quarantine-build-debian12/provenance-red-tests.log`. Test-only `FIC_FIREWALL_PROVENANCE_BASE_REPLAY` сохраняет исходный public API для replay R1–R12.
* Final Debian 12 targeted build/CTest: 28/28 PASS (20 provenance cases + firewall/static/profile/legacy/controller/rollback). Logs `/tmp/fic-quarantine-build-debian12/provenance-green-*.log`.
* Debian 13 и Ubuntu 24.04/26.04 final targeted configure/build/CTest: 27/27 PASS каждый; ALT p11 те же executable cases непосредственно PASS (`ctest` отсутствует). Logs `/tmp/fic-quarantine-{debian13,ubuntu2404,ubuntu2604,altp11}/provenance-*-final.log`; OS IDs проверены.
* Fresh Debian 12 `cmake -S /src -B /build -DFIC_TARGET_PLATFORM=debian-12` и full `cmake --build /build -j2` PASS. Final configure/build после добавления R18–R20 и обновления headers PASS; full `ctest --test-dir /build -E "^mutation_journal_tests$" --output-on-failure`: 166/166 PASS на окончательном source state. Logs `/tmp/fic-provenance-debian12/{configure,build,ctest}-final.log`. Первичный full run 163/163 PASS использовал раннюю CMake регистрацию 17 новых cases.
* Fresh `mutation_journal_tests` отдельно под UID/GID 1000 (`setpriv --reuid=1000 --regid=1000 --clear-groups /tmp/fic-journal-check`) PASS. Permissions/dependencies исправлялись только внутри disposable images.
* Real nft NORMAL/quarantine/IPv6 exception/NORMAL kernel proof PASS. Packet E2E PASS: IPv4/IPv6 input/output/forward, loopback, old unallowed TCP, TCP/UDP exceptions/replies, DNS deny, ND, NORMAL restoration, foreign table. Для routed fixture disposable namespace запущен с IPv4/IPv6 forwarding sysctl; первый запуск без IPv6 forwarding остановился до карантина на NORMAL fixture.
* `git diff --check` PASS; `git show --check` и clean status проверяются при завершении commit. Все runtime проверки — disposable Podman; host security state не менялся.

## Remaining

* Known limitations: существующий manifest-proven ресурс без journal требует явного provenance recovery; root/external writers сохраняют residual races. Ранее документированные inet namespace/L2/offload ограничения карантина неизменны. Real logind/desktop/PAM/SSH E2E не выполнялся.
