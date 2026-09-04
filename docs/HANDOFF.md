# FIC: передача контекста

## Current base

- Ветка: `main`.
- Родитель текущей правки: `72d49e1`.

## Current task

- На Ubuntu 26.04 валидировать sudoers parser-ом активного sudo provider.

## Accepted architecture / invariants

- Provider-linked executable определяется по canonical target доверенного
  selector и строгой platform allowlist provider-to-validator.
- Неактивный parser не используется как fallback.
- Выбранный реальный validator сохраняет package ownership/checksum и runtime
  hash verification; при switch без trust sync применение fail-closed.

## Completed

- Ubuntu 26.04 profile сопоставляет sudo-rs с
  `/usr/lib/cargo/bin/visudo`, classic sudo с `/usr/sbin/visudo.ws`.
- Resolver перечитывает active provider при каждом выборе, поэтому не сохраняет
  stale cache после alternatives switch.
- Profile validation проверяет полноту, нормализацию, уникальность mappings и
  присутствие каждого validator в package-trust candidates.

## Changed areas

- `fic/src/platform`: provider-linked executable contract и resolver.
- Ubuntu 26.04 platform profile.
- Platform profile/resolver tests и sudoers documentation.

## Validation

- `platform_profile_tests` — passed для всех пяти target profiles.
- Ubuntu 26.04 profile: `sudoers_configuration_tests` и
  `command_hash_batch_tests` — passed; target `fic` built successfully.
- Реальный Ubuntu 26.04 container: default sudo-rs alternatives и switch на
  classic sudo подтверждены; все пять форм политик FIC приняты обоими parser-ами.
- Dpkg owner/md5 metadata подтверждены для обоих реальных validator paths.

## Remaining

- Смена alternatives во время уже начатой одной операции остаётся root-only
  административной гонкой; непривилегированный пользователь selector не меняет.
- После этого коммита остаются задачи 3-6 из пользовательского списка.
