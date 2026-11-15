# SSH shared publication — I2 validation

Base: `332be35f254a7daa17887239ef7bddae78cef7d5`, branch `main`.
Production contract: [activator propagation](verified-config-service-activator.md#propagation-строгий-default-и-доверенный-ssh-path).
Это проверка новой production-реализации, отдельно от исторических R2/P2.

## Воспроизводимость и изоляция

SSH: `FIC_SSH_NATIVE_SCENARIO=shared FIC_SSH_NATIVE_BUILD_DIR=<build> bash
 tests/integration/verified_config_service/openssh_native/run-native.sh IMAGE PLATFORM`.
Отдельный scenario выбирает только native fixture, не разрешение в production.
Без scenario запускается прежний native SSH gate.

SSSD: `FIC_SSSD_I3_SCENARIO=shared-boundary bash
 tests/integration/sssd-i3/run-native.sh IMAGE ubuntu-26.04`.
Source manifest включает boundary fixture и проверяется после запуска.
Это targeted regression, не новая полная SSSD matrix.

Общий native suite: `tests/integration/verified_config_service/` и
`verified_config_service_native_tests` (явный opt-in disposable guard).
T1–T4 выполняются в `SharedPublicationCases.h`; real notify reader через systemd
проверяет FD mount ID/bytes/EnvironmentFile. Собственный SSH служит отдельной
проверкой реального OpenSSH, а не подменяется этим reader.

Runtime containers: настоящий systemd PID1, private PID/mount/cgroup namespaces,
network none, без host binds/ports. Перед shared fixture доказано отсутствие
унаследованных shared/master связей. Только внутри disposable container
создаётся shared root/run; production не меняет propagation. Build containers
имеют read-only source bind, runtime containers — только tmpfs `/run`/`/tmp`.
Все userlands используют общее Docker/WSL ядро, не пять distro kernels.

## Проверяемый scope

Shared SSH gate: первый owned `ssh_use_pam` apply; same-process receipt repeat;
новый driver process без receipt; RO EROFS + A/C/P/readiness/listener proofs;
active verified release; foreign-compliant scalar acquisition; REFRESH и repeat;
persistent drift через preopened original FD; cleanup failure с
`primaryStatus=Success`, итогом `CleanupFailed`; offline release validation.
Directory Include snapshot и штатный protected EnvironmentFile участвуют в proof.

T1: slave без nested mount — propagated copies исчезают после local cleanup.
T2: slave с nested mount — local Success, downstream directory snapshot остаётся RO.
T3: shared-slave с peer и nested mount — то же ограничение для downstream copies.
T4: private control — downstream не получает snapshots.
Для всех проверены пустые local residuals/cleanupErrors, восстановленная persistent
view и обычный identity-checked cleanup искусственной topology самим harness.
Успех T2/T3 не означает глобального cleanup или аттестации чужих consumers.

Unknown optional metadata проверяется pure production predicate в обоих режимах;
строгие defaults проверены для activation/preflight/snapshot validation.
Прежний generic native suite сохраняет negative manifest/RO/publication,
interference/foreign mount, EBUSY/residual и failed-service checks.

## Результаты

Дата: 2026-11-15. Все нижеуказанные gates выполнены на production engine I2.

| Userland | OpenSSH package (без epoch) | systemd | Shared root/run | Прежний SSH gate: PASS cases/groups |
|---|---|---|---|---|
| Debian 12 | 9.2p1-2+deb12u10 | 252.39-1~deb12u2 | PASS (8 groups) | 30 |
| Debian 13 | 10.0p1-7+deb13u4 | 257.13-1~deb13u1 | PASS (8 groups) | 30 |
| Ubuntu 24.04 | 9.6p1-3ubuntu13.20 | 255.4-1ubuntu8.18 | PASS (8 groups) | 52 |
| Ubuntu 26.04 | 10.2p1-2ubuntu3.8 | 259.9-0ubuntu0.1 | PASS (8 groups) | 52 |
| ALT p11 | 9.6p1-alt7 | 258.9-alt1 | PASS (8 groups) | 65 |

* Общий native suite Ubuntu26: **208 PASS, 0 SKIP**, включая T1–T4 и прежние private/non-shared slave/negative tests.
* SSSD Ubuntu26: private activation/EROFS и повтор после отказов — A/B/C/P Proven; shared и shared-slave — отказ без activation attempt/смены InvocationID; source receipt проверен. Это не полная SSSD native matrix.
* Полный configure/build Debian12 с настоящими PAM/Qt dev libraries: **PASS** (`cmake --build … -j6`). Четыре targeted CTests и все service/SSSD CTests в широком прогоне — PASS.
* Shell/Python syntax, OpenSSH harness self-test, `git diff --check` — PASS.

### Широкий CTest: не зелёный

Root: **219 PASS, 4 SKIP, 6 FAIL** (229). Пять существующих отказов
подтверждены на отдельном чистом архиве base SHA: `path_layout_static_checks`
(старое требование Type=simple), `platform_profile_static_checks` (старый
wait-daemon), `incident_state_lifecycle_static_checks` (RPM manifest),
`desktop_environment_architecture_static_checks` (Type=notify assertion),
`identity_policy_hierarchy_tests` (activation recommendations; отдельно собран
и исполнен на base). В первоначальном root run path-layout остановился раньше
на Git dubious ownership; дополнительный UID1000 run с safe.directory дошёл до воспроизведённого base assertion.
Шестой — `mutation_journal_tests`: permission-based fault injection под root;
тот же binary PASS без root. MutationJournal в I2 не менялся.

Дополнительный full run UID1000 без passwd entry: **204 PASS, 13 SKIP, 12 FAIL**.
Помимо пяти base failures, не прошли `session_agent_install_layout_tests`,
`mode_and_owner_tests` (SEGFAULT), `incident_recovery_group_tests` (abort),
`rollback_executor_tests` (identity lookup), `pam_configuration_tests`,
`display_manager_transaction_tests`, `pam_dependency_contract_tests`.
Этот контекст не удовлетворяет root/account prerequisites части suite; все семь
дополнительных тестов PASS в root run. Их внутренние проблемы вне I2 не исправлялись;
непривилегированный прогон тоже не объявляется успешным.
Native test SKIP в обычном CTest не подменяет отдельные opt-in native результаты выше.

### Непрошедшие предварительные попытки

Первый Ubuntu26 shared run отказал на owned repeat с существующей диагностикой
`descriptor identity unavailable`. Следующие полные shared gates PASS без
изменения production code; причина единичного отказа не установлена, не выдаётся
за доказанный дефект среды или FIC. Raw failure: `/tmp/fic-i2/ubuntu2604-initial-failure.json`.
ALT fixture первоначально не дождался initial Type=simple listener; добавлено
bounded ожидание только fixture. Ctest/ss отсутствовали в исходных test images,
добавлены только туда. Медленные Debian archive endpoints заменены подписанным
зеркалом в test image; apt signature checks не отключались.

### Receipts

Полные sanitized reports: `/tmp/fic-i2/native-*/evidence/`, generic:
`/tmp/fic-i2/generic-runtime.json`; SSSD:
`build-sssd-i3/ubuntu-26.04/native/{results,completion}.json`.
Ни private keys, ни сырые бинарные archives в commit не добавлены.

| Platform | Driver SHA-256 | Shared report SHA-256 |
|---|---|---|
| Debian 12 | `4c41f8adfaf112fc9208bfac8cf1ccd0d79dd0c317e252514a706680ea5e9acc` | `a6057587c18e6b5788661da58eff5f22535d2f604a651ba3a228aa948fd23dcf` |
| Debian 13 | `f5b71ece86b2dc46ac00b1eb211ab6c9bb4d8e47e1f1bc1c4494c5616599c7e1` | `842a8cbf2378267d898bd6bc7c3968fb1b3176486e6d49fc358c74bd65093c35` |
| Ubuntu 24.04 | `bac40c60d405f4d24b961f64a9928e430c81e487588374d7e6ab64578a1e2a22` | `f07043b88f05d36e2f230371616ae9443b7dba381f62b9f5d8c3d95fde885dc9` |
| Ubuntu 26.04 | `6dd265e59dd0053f7df0cb0f286d6dff4fb6024afeaa0e5d1f0cd31d0b618e57` | `2108f3091368ef1138de85fac54631bad4371c1827afb7082310a93b3c20dd4b` |
| ALT p11 | `0a96e09e0de5aa3e58517536c5a145c4276beb05213a574a7a6843fecf0be298` | `698b95f8fb17a2619465aecacc485d7c98c9e35a0be38a1cee7828ec5e48db2f` |

Production input hashes (одинаковый исходный diff для всех builds):

* `fic/src/service/VerifiedConfigMountSupport.h`: `d3234e29f6573ec0f76e1858079c08468cfecfd82f1b2179d7f74b4686894537`
* `fic/src/service/VerifiedConfigMountSupport.cpp`: `9be1c984185d70c95a7838e901247dff4ed325c88a24acf57322354678c0cc11`
* `fic/src/service/VerifiedConfigActivationProof.h`: `6e6c9649f51d136809c88be4c5e6ca5451f65bb3dfcda4da2ba4f341d3ef6b8c`
* `fic/src/service/VerifiedConfigServiceActivator.cpp`: `27b1a39886eb4b89d15c1f48ee60d959ed0516e5cb486441e9b6348b5622a4ef`
* `fic/src/service/ssh/SshVerifiedActivationAdapter.cpp`: `dc8545d3865214d7fb0628e3968eb97faa3a2532133bee44abec90bac507625d`

## Ограничения

VM `192.168.1.50`: **NOT_RUN** — snapshot/clone и виртуальная консоль не подтверждены.
SSH, mounts и security state реальной машины не менялись. Container native PASS
не является VM/hardware/distro-kernel проверкой или полной authentication/PAM
аттестацией. Config/runtime proof и local cleanup proof различаются; downstream
copies могут сохраняться. Прежние CAP_SYS_ADMIN read/check/action гонки остаются.
