# Debian SSH verified policy validation

## Проверенная реализация

Debian12/13 production `Ssh::apply()` → CAS/durability → существующий SSH adapter
и generic RO-snapshot engine → native restart/READY → cleanup/P → journal commit.
Контракт: [adapter](ssh-verified-activation-adapter.md#debian-policy-lifecycle).
M1 не менялся; module runner разрешает проверить настоящий policy backend без
запуска daemon startup и без подделки Installed/fence/package proofs.

## Native environment

Все runtime-запуски — одноразовые Docker, systemd PID1, private namespaces/cgroups,
network none с loopback, без host binds/ports/SSH/PAM. Образы уже подготовлены;
в этом этапе их Containerfile заново не собирался.

| Profile | openssh-server package | systemd package | Результат |
|---|---|---|---|
| Debian12 | `1:9.2p1-2+deb12u10` | `252.39-1~deb12u2` | 30 generic + 59 adapter + 24 module case groups PASS |
| Debian13 | `1:10.0p1-7+deb13u4` | `257.13-1~deb13u1` | 30 generic + 59 adapter + 24 module case groups PASS |

Binary probes: OpenSSH_9.2 / OpenSSL3.0.22 и OpenSSH_10.0p2 Debian-7+deb13u4 /
OpenSSL3.5.7 соответственно. Package label и binary version записаны отдельно,
не выводились один из другого. Общий kernel: `6.6.87.2-microsoft-standard-WSL2`.

Immutable image IDs:

* Debian12: `sha256:8bfd868d192ac076aa62bd985829ab6289b6c5b88079cb569cb1d903013cb72c`.
* Debian13: `sha256:6e20048bc0a8cf200d08abb088ae8a05d7a658661b37d6e2c729a89dcb12aa28`.

## Что именно проверено

* Все пять реальных классов политик, доверенный fixture NET.conf, настоящий
  MutationJournal и настоящий системный sshd; без fake command runner на module path.
* Foreign compliant состояние не получает ownership. Fresh managed изменения
  подтверждаются новым PID/InvocationID и listening socket нового sshd на 2244.
  Последующие полные проходы сохраняют invocation, main bytes и journal ownership.
* Receipt инвалидируется после административного restart или изменения main input.
  Другие enabled values входят в receipt только после proof на том же RO snapshot.
* Stock defaults/HostKeys, Include negative set/вложенные Include, unrelated Match,
  ограниченные Description/CPUWeight drop-ins. Relevant Match/external Include,
  symlink/invalid inputs и лишний foreign Port не дают false SUCCESS.
* Disabled-active, disabled-inactive, enabled-inactive-no-Job. На настоящем pending
  restart ptrace event-stop удерживает fixture-owned старый sshd; admission реально
  наблюдает deactivating. Управляемое освобождение даёт success, invalid next
  startup — failure, оставленный barrier — bounded timeout. Обычный SIGSTOP не
  используется как ненадёжная замена этого барьера.
* Отдельный deterministic unit matrix покрывает enablement × runtime states,
  activating/auto-restart → active/failed/deadline и late disabled proof. Это
  controlled-observation тест production loop, не выдаваемый за все native bus states.
* Реальные stop/disable/foreign restart после READY, а также disable/restart в
  последнем confirmation window запрещают полный SUCCESS, сохраняя ранние A/B/C facts.
* Before-CAS disable/input/main races не приводят к записи FIC. After-save stop,
  disable, input/main drift, durability failure и lost writer observation сохраняют
  effect/provenance и блокируют следующий apply. Journal commit failure после
  реального runtime success блокирует доступ к journal и последующую mutation.
* Несовместимые реальным образом загруженные ExecStart `-f`/`-o`, ExecStartPre,
  EnvironmentFile и PrivateMounts overrides отвергаются без config/journal/runtime
  mutation. Тестовые overrides удаляются fixture, vendor unit bytes не меняются.
* CleanupFailed, persistent metadata/content drift, original FD/mount races,
  unknown proof и native NonCompliant остаются раздельными результатами.
* Stock start-limit-hit воспроизведён на раннем module тесте; исправление — bounded
  own restart budget, а не изменение/reset unit limits. Итоговая five-policy
  последовательность проходит со штатными лимитами.

## Regression gates

* Полный Debian12 cached project build и full CTest: **206 PASS, 4 SKIP, 0 FAIL**,
  210 total, 174.47s в последнем запуске. Включены singleton/maintenance native opts.
  Skips: standalone privileged generic native target (проверяется отдельным runner),
  package PAM hooks opt-in и две opt-in legacy research reproductions. M1 research
  не включалось в безопасный SSH runtime gate.
* Standalone SSH provenance gate: Debian12/13, Ubuntu24.04/26.04, ALT p11 — по
  **55 PASS/0 FAIL**, включая R1/R1b/R5, новые verified transaction faults, общий
  resource mutex/Prepared disable gate и production platform dispatch. На Debian
  дополнительно по три настоящих OpenSSH semantics probes PASS.
* Generic native regression: Ubuntu24.04/26.04 — по **202 PASS/0 SKIP**; ALT p11 —
  **201 PASS/1 SKIP** (известная stock lower-layer empty SSH Include/copy-up fixture).
* `git diff --check` PASS. Symbol scan production fic подтверждает отсутствие
  SSH save-outcome/adapter test entrypoints.

## Воспроизведение

Из корня checkout с доступным Docker и указанными подготовленными образами:

```sh
bash tests/integration/verified_config_service/openssh_native/run-native.sh fic-ssh-audit:debian12 debian-12
bash tests/integration/verified_config_service/openssh_native/run-native.sh fic-ssh-audit:debian13 debian-13
bash tests/integration/ssh-provenance/run-native.sh debian12 debian13 ubuntu2404 ubuntu2604 alt-p11
bash tests/integration/verified_config_service/run-native.sh fic-ssh-audit:ubuntu2404 ubuntu-24.04
bash tests/integration/verified_config_service/run-native.sh fic-ssh-audit:ubuntu2604 ubuntu-26.04
bash tests/integration/verified_config_service/run-native.sh fic-ssh-audit:alt-p11 alt-p11
```

Root project build использует отдельный Debian12 Docker build cache, source RO,
DAC_OVERRIDE/DAC_READ_SEARCH dropped, root-owned /build на время проверки,
`FIC_DAEMON_SINGLETON_NATIVE=1`, `FIC_MAINTENANCE_NATIVE=1`,
`QT_QPA_PLATFORM=offscreen`; команды `cmake --build /build -j4` и
`ctest --test-dir /build --output-on-failure` последовательно, без relink во время
CTest. Build-owner возвращается пользователю после завершения.

Локальные подробные logs: `build-m1-evidence/ssh-release-{native-debian12,native-debian13,final-full-debian12}.log`,
`ssh-integrated-provenance-matrix.log`, `ssh-integrated-generic-*.log`.
Sanitized native results/versions/namespace/container inspect —
`build-openssh-native/debian-{12,13}/evidence/` и соседний container-inspect.json.
Эти generated artifacts не являются source и не коммитятся. Приватные ключи,
backup и policy references остаются в disposable container workspace.

## Границы результата

Это module/systemd/OpenSSH end-to-end и lower-level regression, не полный
production daemon/IPC/package/M1/PAM-login тест. Connection probes доходят до
identification/server KEXINIT, без завершённого authentication. Не проверены
другие kernels/VMs/hardware, непрерывный enforcement и защита от privileged ABA.
Shared publication parents требуют заранее подготовленной безопасной границы;
FIC не меняет global propagation и не provision-ит её самостоятельно.

Schema2 strict REFRESH и автоматический semantic recovery Prepared не реализованы:
операции явно отказывают с сохранением provenance. Это разрешённая граница текущего
ТЗ, а не замаскированный rollback. ALT activation/compensation остаётся legacy;
Ubuntu production strict policy path Unsupported до отдельной
[socket activation задачи](ubuntu-ssh-socket-activation-spec.md).
