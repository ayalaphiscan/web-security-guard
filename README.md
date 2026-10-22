# Web Security Guard

[![Claude Code Plugin](https://img.shields.io/badge/Claude%20Code-plugin-d97757)](https://docs.claude.com/en/docs/claude-code)
[![Version](https://img.shields.io/badge/version-0.4.0-blue)](https://github.com/ayalaphiscan/web-security-guard/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Built with Claude Fable 5](https://img.shields.io/badge/built%20with-Claude%20Fable%205-d97757)](https://claude.com/claude-code)

A security plugin for [Claude Code](https://docs.claude.com/en/docs/claude-code) and Claude Cowork that turns Claude into a security-aware engineer. It bundles 8 skills, 2 slash commands and ready-to-deploy infrastructure templates covering the full lifecycle: hardening, runtime patching, secure Supabase, authentication, payments privacy, active defense, stealth architecture and CI security. All skills are **bilingual (English + Italiano)**.

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
| `supabase-sicuro` | Secures Supabase projects: RLS on every table, explicit grants (required from 30 October 2026), SECURITY DEFINER functions, storage policies, publishable/secret keys, Auth settings, tests as different users |

**Commands:** `/proteggi-sito` (install all protections in the current project) · `/security-audit` (full security audit with report)

**Battle-tested defense agent.** The included `guardian` middleware (plain Node.js, zero runtime dependencies; the Fortress proxy now needs only Express and runs on Node 22.23.4) handles malformed-URI evasion attempts, prunes its memory maps to avoid unbounded growth, and ships in two flavors: standard (with explanatory 403s) and stealth (attackers get their connection dropped, no response at all).

## Installation

### Claude Code
```
/plugin marketplace add ayalaphiscan/web-security-guard
/plugin install web-security-guard@web-security-guard
```

### Claude Cowork (desktop app)
Download `web-security-guard.plugin` from the [latest release](https://github.com/ayalaphiscan/web-security-guard/releases/latest) and install it from **Settings → Capabilities**.

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
