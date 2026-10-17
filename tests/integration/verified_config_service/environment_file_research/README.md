# EnvironmentFile research — disposable systemd PoC

**Изменяет только специальную fixture внутри нового disposable Docker. Не запускать
binary вручную на хосте или в рабочем контейнере.**

[Архитектура и результаты](../../../../docs/verified-config-environment-file-research.md).

```sh
bash tests/integration/verified_config_service/environment_file_research/run-native.sh \
  fic-ssh-audit:debian12 debian-12
```

Пять использованных пар image/profile:
`fic-ssh-audit:debian12` / `debian-12`, `:debian13` / `debian-13`,
`:ubuntu2404` / `ubuntu-24.04`, `:ubuntu2604` / `ubuntu-26.04`,
`:alt-p11` / `alt-p11`. Образы из предыдущего native audit содержат systemd,
C++17 compiler, CMake, pkg-config, libsystemd headers и build dependencies fic-core.
Рецепт среды: native distro userspace с systemd установленным как PID1 command;
при установке packages в build image запретить service autostart; не модифицировать
stock SSH units/config. `run-native.sh` использует Docker с private cgroup/mount
namespace, --network none, tmpfs /run,/tmp и без host security directories/socket.
Root и privileged нужны для **временных fixture mounts**, не для host изменений.
Image command должен загружать systemd (обычно `/sbin/init`).

Runner собирает только `environment_file_research`, source mounted read-only,
передаёт binary в новый контейнер и удаляет контейнер по EXIT trap. Bootstrap
`show-environment` retry — readiness инфраструктуры; все экспериментальные гонки
синхронизированы SOCK_SEQPACKET barriers, не случайными sleep. Timeout READY
проверяет настоящую systemd deadline, не timing guess.

Harness требует root, `/.dockerenv`, PID1=systemd и явный
`FIC_ENV_RESEARCH_DISPOSABLE=1`; отказывается использовать существующий fixture root.
Работает только с `/run/fic-env-research`,
`/run/systemd/system/fic-env-research.service` и своим binary. Никаких команд
штатному ssh/sshd unit, policy apply, enrollment или FIC config write нет.

Fixture сообщает только три искусственных env variables, свой argv, namespace,
SHA256/mount ID/inode actual config read FD; закрывает FD перед READY. Config path
выбирается synthetic environment и искусственными `-f`/`-o FixtureConfig=...`;
**это не запуск sshd и не proof native SSH parser**. Реальные процессы condition/
pre/main используют ту же IPC fixture с различными roles. Прямое наблюдение PID1
чтения — отдельный FIFO experiment; FIFO не предлагается как production input.

Переиспользованы существующие FIC `openAbsolute/readTree/copyTree/verifyTree`,
`identity`, `requireSafePublicationParent/requireReadOnly`, `MountObserver`,
`readLaunchContract`, `ContentDigest`, `AtomicFileWriter`. Setup systemctl идёт
через `PlatformExecutableResolver` и `ProcessExecutor`, как в существующем native
fixture; **не VerifiedProcessExecutor**, потому что это создание fixture и trust
store намеренно не enroll. Production execution contract не меняется.

`Snapshot` — только лабораторный publisher, не альтернативный activator: нет
полного preflight, observer/contract loop, persistent journal, crash adoption,
полного CAS-before-publication/recovery. Он не возвращает ActivationResult/Success.
В negative original-replacement experiment отдельно проверяется, что existing
production identity gate обязан отказать; последующая лабораторная публикация
нужна только показать byte isolation. Positive results нельзя объявлять успешной
production activation. Cleanup проверяет own identity, закрывает inspection FD,
делает обычный umount; EBUSY — false, не успех. Forced Docker teardown — только
утилизация всей disposable среды, не production recovery policy.

Exit0 и `EVIDENCE` означают, что все assertions/negative expectations прошли.
Сводка может быть извлечена без логов всего окружения:

```sh
# После сохранения stdout runner в research.log:
python3 - <<'PY'
import json
for line in open('research.log'):
    if line.startswith('EVIDENCE '):
        print(json.dumps(json.loads(line[9:]), indent=2))
PY
```

Native regression будущего production изменения должен использовать сам activator
и отдельно доказывать отказы/cleanup; этот research suite его не заменяет.
