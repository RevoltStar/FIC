# Security Policy

## Supported versions

FIC has not published a stable, security-supported release yet. Development
builds must not be treated as production-supported software.

| Version | Security status |
| --- | --- |
| `main` / `0.0.0-alpha` | Reports are accepted, but there is no compatibility or remediation SLA. |
| Stable releases | None published. |

This table will be replaced with explicit supported release ranges when the
first stable version is published.

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in a public issue, discussion, pull
request, or commit.

Use GitHub Private Vulnerability Reporting:

[Report a vulnerability privately](https://github.com/RevoltStar/FIC/security/advisories/new)

If the private reporting form is unavailable, open a public issue that asks the
maintainer to enable private vulnerability reporting. Do not include any
vulnerability details in that issue.

Include as much of the following as possible in the private report:

- the affected FIC version or commit;
- the target operating system and version;
- the required privileges and preconditions;
- the security impact and affected trust boundary;
- reproducible steps or a minimal proof of concept;
- suggested mitigations, if known;
- sanitized logs or diagnostics that do not contain credentials, personal
  data, private keys, or other secrets.

## Security scope

Examples of in-scope issues include:

- bypassing Unix socket permissions or the `fic` group authorization boundary;
- local privilege escalation or unintended command execution as `root`;
- arbitrary file access or modification through the privileged daemon;
- bypassing trusted-command verification or package lifecycle protections;
- IPC parsing, framing, authentication, authorization, or denial-of-service
  flaws with impact outside the caller's intended privileges;
- policy enforcement bypasses that contradict documented behavior;
- device-control, session-agent, database schema validation, or package
  lifecycle flaws that cross a security boundary;
- vulnerabilities in third-party components that are demonstrably present and
  exploitable in an FIC binary package.

Membership in the `fic` operating-system group intentionally grants full
administrative access to the daemon API. A group member invoking documented
administrative operations is not, by itself, a security vulnerability. A way
to obtain that membership without authorization or to exceed the documented
boundary is in scope.

General feature requests and hardening suggestions without a concrete security
impact should be reported through a regular public issue. The authoritative
list of declared target operating systems is maintained in the
[Target platforms section of the README](README.md). A defect observed only on
an operating system outside that list should normally be reported through a
regular public issue. Report it privately instead if it demonstrates a
distribution-independent vulnerability in FIC or can also affect a declared
target platform.

## Response and coordinated disclosure

The maintainer aims to:

- acknowledge a private report within five business days;
- provide an initial assessment within ten business days;
- provide a status update at least once every fourteen days while the report
  remains active.

These are response targets, not a guaranteed remediation SLA. Fix timing
depends on severity, exploitability, affected versions, and the validation
required on supported operating systems.

Please coordinate public disclosure with the maintainer. When appropriate, the
maintainer will publish a GitHub Security Advisory, identify affected and fixed
versions, request a CVE, and credit the reporter if they want to be named.

## Research conduct

Test only systems that you own or are explicitly authorized to test. Avoid
privacy violations, service disruption, destructive actions, persistence, and
access to data beyond what is necessary to demonstrate the issue. Stop testing
and report immediately if sensitive data is exposed.

The project does not currently operate a paid bug-bounty program.
