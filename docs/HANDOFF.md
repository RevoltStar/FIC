# FIC handoff

## Current base

* Branch `main`; focused implementation based on `d10900e28b8eb273a4d24e91d344a913b01294f9`.

## Current task

* Сетевой карантин через единый FIREWALL coordinator — реализован и проверен; requested focused commit.

## Accepted architecture / invariants

* `IncidentController` выбирает NORMAL/INCIDENT_QUARANTINE: ACTIVE + effective ISOLATE требует карантина. Недоказанные mode/state означают ACTIVE/ISOLATE; более строгая текущая requirement при failed persistence также учитывается. Thin network adapter не исполняет nft самостоятельно.
* Все backend apply/reconcile/ordinary rollback проходят coordinator. Controller transitions и firewall operations сериализованы общим in-process lock. Failed registry rebuild подавляет dependent reconciliation.
* Quarantine: `inet fic_incident_quarantine`, filter input/output/forward, priority 0, DROP; loopback input/output разрешён. Ordinary FIC tables/exclusive enforcement отсутствуют. ENABLE использует allow exceptions, DISABLE сохраняет строгий карантин без exceptions.
* Stateful replies требуют established + reply direction + обратный разрешённый tuple. IPv6 exceptions добавляют только ND types 135/136, code 0, hoplimit 255. Полный contract/schema/limitations — `fic/README.md`, раздел FIREWALL.
* Ownership: root-owned 0640 `firewall_ownership` рядом с lockstatus; durable before/after структуры и случайные nonce фиксируются до единого nft batch. Fresh полная kernel proof обязательна; unchanged ruleset не пересоздаётся.
* Пользователь явно принял отказ/DEGRADED для legacy таблиц без manifest. Имя/комментарий не дают права destructive replacement; automatic adoption отсутствует.
* Выход восстанавливает текущую ordinary configuration, включая direct apply после исчезновения quarantine table. Durable UNLOCKED не откатывается при cleanup failure; последующий reconcile повторяет cleanup.
* Quarantine/normal no-op не теряет существующие ordinary journal obligations. Incident policy не enrolled в ordinary rollback. Model A, PAM/SSH subsystem и incident token format не перепроектированы.

## Completed

* Coordinator/backend/compiler/verifier, incident adapter и production wiring; default policy/config/ru/en; bounded runtime re-proof и registry failure guards.
* Исполняемые profile/controller/fake nft tests, RED/GREEN legacy replay и disposable packet harness.
* Документация profiles, ownership, schema, transitions, rollback/recovery и ограничений.

## Changed areas

* `fic/src/modules/firewall/`, incident controller/adapter/synchronization, daemon registry/main, rollback enrollment, FIREWALL config/lang.
* `tests/CMakeLists.txt`, firewall/incident/rollback tests; `fic/README.md`, architecture/rollback docs.
* `tests/fic/modules/firewall/packet_tests.py` — standalone disposable packet harness; включён explicit force-add несмотря на общий Git ignore.

## Validation

* RED C13 до implementation: unsupported nft entry был принят. RED C14/C15/F13: отдельный executable с production FIREWALL sources из base archive; wrong hook, permissive expression и name-only destructive mutation провалили соответствующие assertions. Current replay GREEN.
* Fresh Debian 12 configure: `cmake -S /src -B /build -DFIC_TARGET_PLATFORM=debian-12`; full `cmake --build /build -j2` PASS. Full `ctest --test-dir /build -E "^mutation_journal_tests$" --output-on-failure`: 146/146 PASS на окончательном source state, включая firewall/profile/legacy/controller/Model A/rollback tests.
* `mutation_journal_tests` отдельно под UID/GID 1000 PASS (`setpriv --reuid=1000 --regid=1000 --clear-groups /tmp/fic-journal-check`). В disposable image исправлены только мешавшие 0700 ancestors/library permissions; host не изменялся.
* Debian 13, Ubuntu 24.04/26.04 targeted configure/build и 7 CTest cases PASS; ALT p11 те же executables непосредственно PASS. Final reruns после последней правки PASS. OS identifiers образов проверены. Недостающие PAM/GIO/git dependencies добавлялись только в disposable containers.
* Real nft kernel profile/IPv6 exception proof PASS. Packet E2E PASS: IPv4/IPv6 input/output/forward, loopback, старый unallowed TCP, TCP/UDP exceptions/replies, DNS deny, IPv6 ND, NORMAL restoration, foreign table. Routed leg использует static neighbour fixture; ND отдельно проверен на exception peer с очисткой neighbour cache.
* `git diff --check` и firewall static checks PASS. `git show --check` — после focused commit.

## Remaining

* Known deployment limitation: legacy/unowned/drifted reserved objects требуют явного ownership recovery; FIC не удаляет их автоматически.
* Inet filtering одного namespace не обеспечивает полный L2/ARP/bridge/netdev/other namespaces/flowtable/offload containment; RA/PMTU и continuous anti-root enforcement не заявляются. Privileged external writers сохраняют residual races. Real logind/desktop/PAM/SSH E2E этой задачей не выполнялся.
