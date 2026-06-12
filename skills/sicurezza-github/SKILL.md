---
name: sicurezza-github
description: Aggiunge alle repository GitHub workflow di sicurezza automatici - scansione dipendenze vulnerabili, ricerca di segreti nel codice, analisi statica CodeQL e Dependabot. Trigger - "sicurezza repo", "scansione repository", "dependabot", "secret scanning". EN - Adds automated security workflows to GitHub repositories - vulnerable dependency scanning, secret/key detection in code, CodeQL static analysis and Dependabot. Triggers - "repo security", "security GitHub Actions", "repository scanning", "dependabot", "secret scanning".
---

# Sicurezza GitHub · GitHub Security

> 🇮🇹 Versione italiana qui sotto · 🇬🇧 [English version below](#github-security-english)

Quando un progetto ha (o avrà) una repository GitHub, installare i file di sicurezza nella directory `.github/` della repo. I template pronti sono in `references/`.

## File da installare nella repo

1. `.github/workflows/security.yml` — da `references/security-workflow.yml`: a ogni push/PR e ogni notte esegue scansione segreti (Gitleaks), audit dipendenze (npm/pip) e analisi statica CodeQL.
2. `.github/dependabot.yml` — da `references/dependabot.yml`: PR automatiche di aggiornamento per dipendenze vulnerabili.

Adattare al linguaggio del progetto: lasciare il job `npm audit` solo se c'è `package.json`, `pip-audit` solo se c'è `requirements.txt`/`pyproject.toml`, impostare i linguaggi CodeQL corretti (`javascript`, `python`, ecc.).

## Regole
- Verificare che `.gitignore` escluda `.env` e credenziali PRIMA del primo push. Se un segreto è già finito nella history, va considerato compromesso: ruotarlo subito (cambiare la chiave dal provider), non basta cancellare il file.
- Consigliare all'utente di attivare nelle impostazioni GitHub della repo: Secret scanning + Push protection, Dependabot alerts, branch protection sul branch principale (review obbligatoria, status check del workflow security).
- I workflow falliscono la build se trovano segreti o vulnerabilità high/critical: spiegare all'utente che è voluto.

## Limite da comunicare
Questi workflow proteggono il codice e le dipendenze, non bloccano gli attacchi al sito in esecuzione: per quello servono la skill difesa-attacchi (middleware) e un WAF/CDN davanti al sito.

---

# GitHub Security (English)

When a project has (or will have) a GitHub repository, install the security files in the repo's `.github/` directory. Ready-made templates are in `references/`.

## Files to install in the repo

1. `.github/workflows/security.yml` — from `references/security-workflow.yml`: on every push/PR and nightly, runs secret scanning (Gitleaks), dependency audit (npm/pip) and CodeQL static analysis.
2. `.github/dependabot.yml` — from `references/dependabot.yml`: automatic update PRs for vulnerable dependencies.

Adapt to the project's language: keep the `npm audit` job only if `package.json` exists, `pip-audit` only if `requirements.txt`/`pyproject.toml` exists, set the correct CodeQL languages (`javascript`, `python`, etc.).

## Rules
- Verify `.gitignore` excludes `.env` and credentials BEFORE the first push. If a secret is already in the history, consider it compromised: rotate it immediately (change the key at the provider) — deleting the file is not enough.
- Advise the user to enable in the repo's GitHub settings: Secret scanning + Push protection, Dependabot alerts, branch protection on the main branch (required review, security workflow status check).
- The workflows fail the build when they find secrets or high/critical vulnerabilities: explain to the user that this is intentional.

## Limitation to communicate
These workflows protect code and dependencies; they do not block attacks on the running site — for that you need the difesa-attacchi skill (middleware) and a WAF/CDN in front of the site.
