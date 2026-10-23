# Frozen legacy DEB scripts for native RED reproduction

Exact final `write_fic_dick_postinst` / `write_fic_dick_prerm` heredoc bodies from
`packaging/deb/build-fic-debian12-deb.sh` at commit `2c9e69c` (before M1 package
integration). These are test data, never package producers or runtime helpers.
Keep them frozen: the old installed scripts remain relevant after current
packaging is corrected. Run only via the explicitly opted-in native reproduction
inside a fresh disposable container, never against the host.
