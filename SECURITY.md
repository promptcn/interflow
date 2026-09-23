# Security Policy

## Supported versions

interflow is pre-1.0 and maintained as a single `main` branch. Only the latest
commit / release receives security fixes; there are no LTS or backport
branches. If you are running an older build, upgrade first and re-check before
reporting.

## Reporting a vulnerability

**Do not open public issues, discussions, or pull requests for security
problems.** Use one of these private channels instead, in order of preference:

1. **GitHub private vulnerability reporting** (preferred): open the
   repository's *Security* tab and click *Report a vulnerability*.
2. **Email**: `leo@promptcn.com`, with `[security]` in the subject line.

Include whatever you have:

- Affected component and code path (`core` / `mesh` / `expose` / `identity`
  / `registrar` / `cli` / `certs` / GUI).
- Steps to reproduce, or a proof of concept (relevant config + commands).
- Your assessment of the impact and the attacker position it requires
  (e.g. public internet, authenticated agent, hub control API access).

We aim to acknowledge reports within **7 days**. This is a small maintainer
team: there is no bounty program and no fixed SLA for fixes, but we keep
reporters informed of progress and coordinate disclosure with them.

## Coordinated disclosure

Please allow time for a fix before publishing. We follow fix-then-disclose:
advisories (and CVE requests where warranted) go out after a release contains
the fix. Reporters are credited unless they prefer otherwise.

## Scope

The attacker positions referenced below (public internet, authenticated
agent, hub control API access) and the defenses behind these scope rules
are described in [THREAT_MODEL.md](THREAT_MODEL.md).

**In scope**

- Vulnerabilities in code shipped from this repository: the production
  crates (`crates/core`, `crates/mesh`, `crates/expose`, `crates/identity`,
  `crates/registrar`, `crates/cli`, `crates/certs`, `crates/contract`,
  `crates/util`) and the GUI (`src-tauri/`). `crates/testkit` is a dev-only
  harness and out of scope.
- Vulnerabilities that manifest under documented configurations, including
  defaults.

**Out of scope**

- Compromised trusted credentials (e.g. a leaked tenant CA key, agent
  private key, or hub TLS private key). Key material is the trust boundary
  it is; rotate it.
- Volumetric DDoS that saturates the host's network before interflow sees it.
  Reports of *asymmetric* resource exhaustion in interflow's own handling
  (cheap for the attacker, expensive for the process) are in scope.
- Vulnerabilities in dependencies — report those upstream. If one is
  exploitable through interflow's default configuration, a coordinated report
  here is welcome and we will track the upstream fix.
- Misconfiguration of the host, firewall, or any reverse proxy in front of
  interflow.
