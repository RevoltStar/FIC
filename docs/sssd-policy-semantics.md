# SSSD policy semantics — R2

Research only, executed after R1 commit
`696a4575e55b125617613fa212317c5b76636151`. No production changes.
Versions/launch constraints: [R1](sssd-native-compatibility.md).
Measured commands, native state and proof levels:
[R2 evidence](sssd-semantics-research-evidence.json). Exact distro source/patch
provenance is in source-r1.json; numbered consumer/provider/manpage excerpts and
call references in [source-r2.json](../tests/integration/sssd-research/source-r2.json).
All five versions were inspected, including ALT's applied distribution patch.

## Defaults and values

| Parameter | Section | Native default | Zero | Future FIC value contract |
|---|---|---|---|---|
| offline_credentials_expiration | [pam] | 0 days | No password offline-age limit from this option | Preserve current integer 0..3650 and FIC default 30; distinguish from SSSD default |
| cache_credentials | each [domain/name] | false | Boolean false disables password caching/use, not all auth mechanisms | Fixed true for a proven explicit domain scope |
| account_cache_expiration | each [domain/name] | 0 days | No age-based cleanup for previously logged-in users; see never-logged-in exception | Proposed nonnegative bounded days, 0..3650; future policy default must be separately specified |
| cached_auth_timeout (foreign input) | each domain | 0 seconds | Do not use online cached-password fast path | Read/validate, do not own or change implicitly |

These are not blanket numeric limits imposed by SSSD. `sssctl config-check`
checks allowed INI structure/options, not these ranges/relations comprehensively.
Native all five accept offline -1, 3651 and 24856 at configuration/startup in the
LDAP fixture; signed-int overflow 2147483648 and `abc` fail later reading ConfigDB.
Negative account expiry in the tested offline=30 relation fails LDAP initialization.
Neither syntax acceptance nor successful startup makes negative or overflow-prone
day arithmetic a supported policy value. Installed sources use signed int reads
and day→second multiplication in relevant paths. Do not infer a safe arbitrary
SSSD range from accepted parser input. FIC's existing 0..3650 is independently
bounded and need not be expanded. Invalid cache boolean fails domain loading.

## Loading matrix

| Input | Consumer/source | Load/use moment | Activation requirement | Actual proof available |
|---|---|---|---|---|
| INI graph | monitor, `sss_ini` → confdb_setup/read_ini | monitor initialization before child registration | Full monitor restart, not HUP | R1 changed files vs unchanged ConfigDB/InvocationID; restart loads new value |
| offline_credentials_expiration | LDAP `ldap_get_options`, domain `init_cached_auth_timeout`; PAM cached-auth path `sysdb_cache_auth` | LDAP/domain initialization; cached password attempt reads **ConfigDB**, not INI | Restart to rebuild ConfigDB and consumers | ConfigDB projection + specific backend initialization + local PAM expiry fixture; not a generic consumer-introspection API |
| cache_credentials | `confdb_get_domain_internal`, in-memory sss_domain_info in monitor/backend/responders; sysdb_cache_auth and auth providers | Domain construction; online cache store and cached auth use the domain flag | Restart all relevant consumers; late responder must use same generation | Source bool default/callers; real password cache-disable rejection and reenable reuse |
| account_cache_expiration | LDAP-family `dp_get_options` basic option array → periodic cleanup | Backend initialization; cleanup reads retained options | Restart backend/monitor for supported future activation | Source provider init/cleanup; native LDAP relation rejection; no days-long cleanup test |
| cached_auth_timeout | confdb domain initialization → PAM domain memory | Startup, clamped to nonzero offline age converted to seconds; per-request freshness check | Full restart for consistent projection | Source + native loading fixture; controlled real online cached-password acceptance, not memory-value introspection |

ConfigDB is `/var/lib/sss/db/config.ldb`, not the credential cache
`cache_<domain>.ldb`. Monitor writes its source configuration; children have
their own ConfigDB contexts and in-memory domains/options. LDB dump is not proof
that all children re-read changed values. Directly editing ConfigDB is neither
a supported activation route nor proposed for FIC. No ConfigDB adoption.

Socket-activated PAM may start **after** monitor READY. Native `services=nss`
fixture captures absence of sssd_pam before the request, native PAM sockets and
post-request responder processes. A failed nonexistent-user request is not a
functional auth PASS; it demonstrates lazy startup. Required consumer proof must
pin the responder generation as well as monitor. An offline LDAP backend can
coexist with active/running service and READY; directory connectivity is not
implied. Invalid LDAP options in these single/mixed-domain fixtures caused unit
failure. Do not extrapolate that every later backend failure stops the monitor.

ALT additionally demonstrates that separation directly: root-monitor controlled
configuration with native responder User=_sssd had an active monitor while the
socket-activated PAM responder exited repeatedly (status=3). With the packaged
config-level user=_sssd preserved in a fresh fixture, the native lazy responder
starts normally. The first case is a configuration/identity mismatch, not proof
of an ALT OS defect or a reason to run its responder as root. Debian13/Ubuntu26
have no separate sssd-pam-priv.socket; the dedicated discovery-based lazy gate
starts only existing sockets. Earlier missing-unit attempts remain in evidence.

## Password offline expiration

Source `sysdb_cache_auth` checks cached credential age against
`lastOnlineAuth + days*86400`; zero skips this age cutoff. A successful real
online login seeds the salted SHA512 password cache and online timestamp.
Successful offline password auth updates `lastLogin`/failure counters, **not**
`lastOnlineAuth`: repeated offline use does not extend the online-age window.
Expiration rejects use; it is not secure deletion of a password hash. Other
failure counters/account restrictions can still prevent zero/unlimited login.

Native FUNCTIONAL_AUTH_CONFIRMED on Debian12/13, Ubuntu24/26, ALT p11:

1. Local TLS LDAP posix user, native pam_sss online auth returns PAM_SUCCESS.
2. Terminated LDAP server + native force-offline USR1: cached password succeeds.
3. Restart cache_credentials=false with the same DB: password offline auth fails;
   metadata remains. Reenable does not require recaching in this fixture.
4. With SSSD stopped, fixture ages **only** lastOnlineAuth by three days using
   ldbmodify. offline=1 then rejects, offline=0 then accepts the same password.
   This is controlled timestamp injection, not a three-day wall-clock test.
5. cached_auth_timeout=3600: while LDAP remains running, its actual password is
   changed and the old cached password still succeeds. This confirms a bounded
   online cached-auth path, not that all online successes contact the directory.

This is one synthetic LDAP password account per userland; no corporate directory,
host PAM modifications, Kerberos tickets, smartcard/passkey or AD/IPA logins.

`cached_auth_timeout` is seconds, independent of days. Source clamps it to a
nonzero offline expiry; 0 offline means no such cap. Freshness uses online/current
token timestamps; cached success must not be treated as refreshed authoritative
online authentication. Failure can fall through to backend auth. A policy
receipt should assert effective option loading, not promise every login is online.

## cache_credentials and mechanisms/providers

True permits storing a password-derived salted hash (and applicable long-term
first factor under minimum-length rules), not plaintext or every possible token.
LDAP, Kerberos-backed AD/IPA and proxy have separate cache-store call paths
(ldap_auth.c, krb5_auth.c, proxy_auth.c); in-memory domain bool gates password
cache use. False is not a cache erasure operation. Existing database material
can remain and become usable again after reenable. Do not add automatic cache
deletion on apply/rollback: it is outside ownership and would destroy credentials.

Smartcard uses local certificate/token checks and mapping, not cached password
hash comparison; newer versions also have passkey/local_auth_policy branches.
Version 2.8.2 lacks the newer passkey path, while newer package source capability
does not itself prove build/runtime token availability. In 2.12 the versioned
manual explicitly distinguishes smartcard/passkey offline behavior from password
caching. Do not advertise these two policies as disabling/enforcing all offline
authentication. No physical card/FIDO device was tested: SOURCE_CONFIRMED only,
functional behavior NOT_TESTED for these mechanisms on every profile.

## Account cleanup and provider differences

LDAP-family cleanup removes **whole cached user objects**, which can include
cached credentials, and invalidates associated group membership information.
It is not merely an NSS TTL, password validity or remote account expiration.
Source checks lastLogin, identity-cache expiry/timestamp DB and whether a UID is
logged in; scheduling is backend-dependent. `0` preserves age-unlimited logged-in
accounts, but stale **never-logged-in** identity entries remain eligible for cleanup
even at zero. This nuance is visible in `ldap_id_cleanup.c`, beyond the simplified
manual phrase “keep forever”. Offline successes update lastLogin, so account
cleanup age and lastOnlineAuth credential age are different clocks.

LDAP `ldap_get_options` enforces the relation described in the validator design.
AD `ad_create_sdap_options` and IPA `ipa_get_id_options` load their own option
tables with dp_get_options: they do **not** call that LDAP relation validator in
the inspected sources. Their defaults include account_cache_expiration=0; AD
and IPA setup use shared LDAP cleanup task infrastructure. Proxy has no analogous
LDAP cleanup/relation contract: all six native proxy combinations remained active.
Native attempted AD/IPA with no realm/keytab/directory cannot initialize a usable
backend; those failures do not prove the LDAP relation is enforced for AD/IPA.
Real trust discovery, cleanup and authentication there remain NOT_TESTED.

Recommended offline→cache dependency is therefore semantically appropriate for
password use, but must stay **Recommended**: the global age option is independently
loadable, other mechanisms differ, and a dependency is not a cross-option validator.
