# Web Security Guard

[![Claude Code Plugin](https://img.shields.io/badge/Claude%20Code-plugin-d97757)](https://docs.claude.com/en/docs/claude-code)
[![Version](https://img.shields.io/badge/version-0.5.0-blue)](https://github.com/ayalaphiscan/web-security-guard/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Built with Claude Fable 5](https://img.shields.io/badge/built%20with-Claude%20Fable%205-d97757)](https://claude.com/claude-code)

A security plugin for [Claude Code](https://docs.claude.com/en/docs/claude-code) and Claude Cowork that turns Claude into a security-aware engineer. It bundles 15 skills, 4 slash commands and ready-to-deploy infrastructure templates covering the full lifecycle: hardening, single-page apps, APIs, runtime patching, secure Supabase, location privacy and GDPR, trust & safety for social apps, authentication, payments privacy, active defense, stealth architecture, incident response, domain and email, provider accounts and CI security. All skills are **bilingual (English + Italiano)**.

```
/plugin marketplace add ayalaphiscan/web-security-guard
```

## What's inside

| Skill | What it does |
|---|---|
| `hardening-siti` | Applies security hardening whenever a site/app is built or reviewed: security headers, CSP, HTTPS, input validation, cookies, CORS, uploads, OWASP Top 10 |
| `autenticazione-sicura` | Secure auth flows: email verification codes, 2FA/TOTP, passkeys, password hashing, sessions, account recovery |
| `difesa-attacchi` | Installs a defense agent (WAF middleware for Express) that detects SQLi, XSS, path traversal, brute force and bots — with rate limiting, IP blocklist and a data-preserving lockdown mode |
| `privacy-pagamenti` | Protects payment data: secure Stripe/PayPal integration, webhook signature verification, PCI-DSS, GDPR, data minimization |
| `architettura-fortezza` | Designs a 4-layer "Fortress": invisible reverse-proxy shield, hidden origin server, WireGuard mesh, air-gapped offline vault with encrypted backups. Includes all deployment templates in `references/fortezza/` |
| `sicurezza-github` | Adds automated security workflows to your repos: dependency scanning, secret scanning, CodeQL, Dependabot (npm, pip, GitHub Actions, Docker images) |
| `aggiornamenti-runtime` | Keeps PHP, Node.js, Python and Docker images on supported, patched versions; what to do when an urgent advisory lands (e.g. PHP2Shell and the Node.js release of 21 October 2026) — app-level defenses cannot stop interpreter flaws |
| `frontend-spa` | Single-page apps and static sites (React, Vite…): CSP without inline scripts, XSS sinks incl. map popups, safe links, tokens in the browser, public env vars, source maps, service workers, supply chain |
| `api-sicura` | The OWASP API Security Top 10 (2023) applied to REST, RPC and generated APIs like PostgREST/Supabase, each with a concrete test |
| `privacy-posizione` | Location privacy and sensitive data: server-side grid rounding, no distance oracles, GPS stripped, GDPR art. 9 consent, DPIA, retention, export and erasure |
| `sicurezza-social` | Trust & safety for social and meet-in-person apps: database-enforced blocks, reports and moderation, server-side rate limits, anti-stalking, fake profiles, scams, DSA duties |
| `risposta-incidenti` | Incident response for small teams on managed services: runbook, kill switch, session revocation, key rotation, evidence, recovery, GDPR 72-hour notification |
| `email-dominio` | Domain and email: registrar lock, DNSSEC, CAA, dangling subdomains, SPF/DKIM/DMARC for transactional mail, phishing in your name |
| `account-fornitori` | The team's provider accounts and secrets: 2FA/passkeys, least privilege, GitHub, secret rotation, CI/CD supply chain, offboarding, AI assistants |
| `supabase-sicuro` | Secures Supabase projects: RLS on every table, explicit grants (required from 30 October 2026), SECURITY DEFINER functions, storage policies, publishable/secret keys, Auth settings, tests as different users |

**Commands:** `/proteggi-sito` (install all protections in the current project) · `/security-audit` (full security audit with report) · `/audit-supabase` (database audit with tests as different users) · `/emergenza` (step-by-step incident guide)

**Battle-tested defense agent.** The included `guardian` middleware (plain Node.js, zero runtime dependencies; the Fortress proxy now needs only Express and runs on Node 22.23.4) handles malformed-URI evasion attempts, prunes its memory maps to avoid unbounded growth, and ships in two flavors: standard (with explanatory 403s) and stealth (attackers get their connection dropped, no response at all).

## Installation

### Claude Code
```
/plugin marketplace add ayalaphiscan/web-security-guard
/plugin install web-security-guard@web-security-guard
```

### Claude Cowork (desktop app)
Download `web-security-guard.plugin` from the [latest release](https://github.com/ayalaphiscan/web-security-guard/releases/latest) and install it from **Settings → Capabilities**.

## What's new in 0.5.0 (22 October 2026)

- Seven new skills: `frontend-spa`, `api-sicura`, `privacy-posizione`, `sicurezza-social`, `risposta-incidenti`, `email-dominio`, `account-fornitori`.
- Two new commands: `/audit-supabase` and `/emergenza`.
- `supabase-sicuro`:
  - Realtime (DELETE events are not filtered by RLS, private channels);
  - MFA with `aal2` for staff, platform settings;
  - the `private` schema;
  - pgTAP tests.
- `/security-audit` and `/proteggi-sito` use all the skills; on a static site with a backend-as-a-service they skip the server middleware.
- The GitHub template pins every action to a commit SHA and gives `security-events: write` only to CodeQL.
- Password advice follows NIST SP 800-63B (length, leaked-password check, no forced composition, no lockout that harassers can abuse).
- An independent review of the whole plugin fixed 26 issues: contradictions between skills, unsafe snippets, outdated legal notes.

## What's new in 0.4.0 (22 October 2026)

- New skill `aggiornamenti-runtime`: runtime and interpreter patching, the what-runs-where inventory, the urgent-advisory routine.
- New skill `supabase-sicuro`: RLS, explicit grants from 30 October 2026, functions, storage, keys, Auth.
- Fortress proxy:
  - `node:22.23.4-alpine` instead of the end-of-life `node:20-alpine`;
  - `package-lock.json` with `npm ci`;
  - `http-proxy-middleware` replaced by Node's own `http` (it pulled in `braces`, with an unfixed high-severity advisory);
  - logs and the `LOCKDOWN` flag now in the mounted volume.
- GitHub templates: Node 22.23.4 in the security workflow, Dependabot for Docker images.
- `/security-audit` and `/proteggi-sito` also check the runtime and Supabase.
- Releases are built by GitHub Actions when the version in `plugin.json` changes on main (or on a `v*` tag).

## Usage examples

- *"Build me a login page"* → hardening + secure authentication kick in automatically
- *"Add Stripe subscriptions"* → payment privacy rules are applied
- *"I want my server hidden and my data in a box"* → Fortress architecture, with templates
- `/security-audit` → full report of issues and fixes for the current project
- *"Is my server affected by the new PHP flaw?"* → runtime inventory and patch routine
- *"Add a comments table to Supabase"* → RLS, explicit grants and tests come with it

## Honest limits (by design, stated in the skills)

The public web port can never be invisible — what can be made invisible are SSH, admin, the real origin server and the vault. Large volumetric DDoS still requires an external CDN/WAF. The skills promise *minimal attack surface, unreachable core, recoverable data* — never "unhackable".

## License

[MIT](LICENSE) — © ayalaphiscan (Fede)

---

🤖 Built with **Claude Fable 5** via [Claude Code](https://claude.com/claude-code) — skills, templates and this very README were developed together with the model the plugin runs on.
