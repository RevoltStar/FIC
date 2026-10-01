# FIC: передача контекста

## Current base

- Ветка `main`, фактический HEAD
  `68f6eb068452a137985db8704606681954985d08`.
- Текущая правка не закоммичена; commit только по отдельному запросу.

## Current task

- Исправлены четыре дефекта, найденные при ручной проверке GUI на ALT
  Workstation K 11.4: неверный metadata contract `/etc/sssd/conf.d`, потеря
  rollback diagnostic в `disable_policy`, replay неизменённых GUI policies и
  неверный заголовок `Apply errors` для save-stage failure.

## Accepted architecture / invariants

- File metadata и directory metadata являются независимыми security
  contracts. `sssd.conf` и FIC-owned snippet остаются `root:root 0600`.
  `/etc/sssd` и `/etc/sssd/conf.d` требуют root owner, запрещают group/world
  write, symlink и non-directory, но не фиксируют non-writing group; поэтому
  штатные `root:root 0755` и ALT `root:_sssd 0750` допустимы.
- Старый overload directory verifier сохранён для Kerberos и других callers;
  их строгий contract не ослаблен. SSSD передаёт typed directory options во
  все snippet reads, inspection, commit, proof-bound removal и compensation.
- `disable()` возвращает typed `PolicyMutationResult`; rollback/backend detail
  сохраняется в IPC `message` и затем в ошибке `PolicyService`.
- GUI row хранит исходные отображаемые enabled/value. Invalid source value,
  показанный fallback, сам по себе не dirty и скрыто не переписывается.
- `Save and Apply` различает `SaveFailed` и `ApplyFailed`; валидный
  `apply_module` response с `ok=false` остаётся `Completed` и сохраняет
  detailed apply UI.
- Save по модулю остаётся последовательным и нетранзакционным. Этот follow-up
  намеренно не добавляет module-wide atomic save или batch rollback.

## Completed

- Добавлен `SecureConfigurationDirectoryOptions` и отдельный secure-read
  overload для независимой проверки parent directory.
- SSSD production и tests переведены на directory integrity contract;
  добавлены positive/negative проверки 0750/0755, writable, owner, symlink и
  non-directory, а также rollback release при 0750.
- `disable_policy` теперь возвращает имя policy и исходную rollback/backend
  причину вместо фиксированного `failed to disable policy`.
- `PolicyChange` получил dirty flags; service отправляет только требуемые
  `set_policy_value` и `enable_policy`/`disable_policy` в прежнем порядке.
- GUI показывает `Save errors` при mutation failure и `Apply errors` только
  при transport/protocol failure стадии `apply_module`.

## Changed areas

- `fic/src/modules/identity_access/{shared/configuration,sssd}`
- `fic/src/daemon`, `fic/src/main.cpp`
- `fic-gui/src/features/policies/{services,widgets}`
- targeted daemon, GUI policy, SSSD и rollback tests

## Validation

- Fresh configure: `cmake -S . -B /tmp/fic-build-check
  -DFIC_TARGET_PLATFORM=ubuntu-24.04` — PASS.
- Affected targets `fic`, `fic-gui` и пять targeted test targets — PASS.
- Targeted CTest: `policy_service_tests`, `policy_mutation_result_tests`,
  `rollback_executor_tests`, `identity_configuration_editors_tests`,
  `identity_concrete_policies_tests` — 5/5 PASS.
- `cmake --build /tmp/fic-build-check -j4` — PASS.
- Полный CTest вне sandbox — 116/116 PASS, один root-only test штатно
  skipped (`command_hash_batch_tests`).
- ALT Workstation K 11.4 (`172.17.1.107`): подтверждены
  `/etc/sssd root:_sssd 0750`, `/etc/sssd/conf.d root:_sssd 0750` и
  `/etc/sssd/sssd.conf root:root 0600`. Первый прогон выявил оставшееся
  ошибочное наследование file-group для `/etc/sssd`; после отдельного
  `mainDirectory` contract explicit
  `fic-cli policy disable IDENTITY_ACCESS
  sssd_offline_credentials_expiration` завершился `policy disabled`, rc=0.
- IPC diagnostic path также подтверждён на первом прогоне: CLI получил полную
  backend-причину, а не generic error.

## Remaining

- Интерактивный клик обновлённого GUI на VM автоматически не воспроизводился;
  dirty call sequence и save/apply stages покрыты `policy_service_tests`, а
  обновлённые `fic`, `fic-cli`, `fic-gui` RPM были установлены на VM.
- Known limitation: при последовательном save policy A/B могут сохраниться,
  даже если policy C завершилась ошибкой; module-wide transaction остаётся
  отдельной будущей задачей.
- Не коммитить без отдельного запроса.
