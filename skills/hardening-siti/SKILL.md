---
name: hardening-siti
description: Applica regole di sicurezza (hardening) ogni volta che si costruisce, modifica o revisiona un sito web o un'app. Copre security headers, CSP, HTTPS, validazione input, cookie, CORS, upload, gestione errori e OWASP Top 10. Trigger - "crea un sito", "metti in sicurezza", "hardening", "security headers". EN - Applies security hardening whenever a website or app is built, modified or reviewed. Covers security headers, CSP, HTTPS, input validation, cookies, CORS, uploads, error handling and the OWASP Top 10. Triggers - "build a website", "create an app", "secure my site", "hardening".
---

# Hardening Siti · Website Hardening

> 🇮🇹 Versione italiana qui sotto · 🇬🇧 [English version below](#website-hardening-english)

Quando si costruisce o si modifica un sito/app, applicare SEMPRE queste regole di sicurezza senza che l'utente debba chiederlo. Segnalare nel riepilogo finale quali protezioni sono state applicate.

## Regole obbligatorie

### 1. Security headers
Applicare su ogni risposta HTML:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
```

In Node/Express usare `helmet()`. In Django attivare `SECURE_*` settings. Su hosting statico (Netlify/Vercel/GitHub Pages) usare il file headers della piattaforma. Adattare la CSP alle risorse reali del sito (CDN, font, analytics) — mai usare `unsafe-inline` per gli script; preferire nonce o hash.

### 2. Input e output
- Validare OGNI input lato server (tipo, lunghezza, formato, whitelist). La validazione client è solo UX.
- Query al database SOLO parametrizzate o via ORM. Mai concatenare stringhe in SQL.
- Escapare l'output nei template (autoescaping attivo). Mai inserire input utente in `innerHTML`, `eval`, attributi evento o URL senza sanitizzazione.
- Path file: mai costruire percorsi da input utente; usare ID mappati o `path.basename` + directory fissa.

### 3. Cookie e sessioni
- Cookie di sessione: `HttpOnly; Secure; SameSite=Lax` (o `Strict` per azioni sensibili).
- Rigenerare l'ID sessione al login. Scadenza assoluta e per inattività.
- Protezione CSRF su ogni form/azione che modifica stato (token CSRF o SameSite + verifica Origin).

### 4. CORS
- Mai `Access-Control-Allow-Origin: *` su endpoint autenticati. Whitelist esplicita di origin.

### 5. Upload di file
- Whitelist di estensioni E content-type verificato sul contenuto reale (magic bytes).
- Rinominare i file con ID casuali, salvarli FUORI dalla web root o su storage separato, limitare la dimensione.

### 6. Errori e log
- Mai mostrare stack trace o dettagli interni all'utente; pagina di errore generica + log lato server.
- Loggare login, errori di autenticazione, pagamenti e azioni amministrative (senza dati sensibili nei log).

### 7. Segreti e dipendenze
- Mai chiavi/API key/password nel codice o nella repo: usare variabili d'ambiente e file `.env` in `.gitignore`.
- Generare sempre `.gitignore` con `.env`, `node_modules`, credenziali.
- Usare versioni aggiornate delle dipendenze; consigliare `npm audit` / `pip-audit` (vedi skill sicurezza-github per l'automazione).

### 8. HTTPS
- Tutto il traffico in HTTPS, redirect da HTTP, HSTS attivo. In sviluppo locale va bene HTTP ma documentare la differenza.

## Checklist finale
Prima di consegnare un sito/app, verificare: headers presenti, query parametrizzate, validazione server, cookie sicuri, CSRF, niente segreti nel codice, errori generici, `.gitignore` corretto. Elencare all'utente le protezioni applicate e gli eventuali punti che richiedono configurazione sul suo hosting.

---

# Website Hardening (English)

When building or modifying a website/app, ALWAYS apply these security rules without the user having to ask. In the final summary, list which protections were applied.

## Mandatory rules

### 1. Security headers
Apply to every HTML response (same header block as above).

In Node/Express use `helmet()`. In Django enable the `SECURE_*` settings. On static hosting (Netlify/Vercel/GitHub Pages) use the platform's headers file. Adapt the CSP to the site's real resources (CDN, fonts, analytics) — never use `unsafe-inline` for scripts; prefer nonces or hashes.

### 2. Input and output
- Validate EVERY input server-side (type, length, format, whitelist). Client-side validation is UX only.
- Database queries ONLY parameterized or via ORM. Never concatenate strings into SQL.
- Escape output in templates (autoescaping on). Never place user input into `innerHTML`, `eval`, event attributes or URLs without sanitization.
- File paths: never build paths from user input; use mapped IDs or `path.basename` + a fixed directory.

### 3. Cookies and sessions
- Session cookies: `HttpOnly; Secure; SameSite=Lax` (or `Strict` for sensitive actions).
- Regenerate the session ID at login. Absolute and inactivity expiration.
- CSRF protection on every state-changing form/action (CSRF token or SameSite + Origin check).

### 4. CORS
- Never `Access-Control-Allow-Origin: *` on authenticated endpoints. Explicit origin whitelist.

### 5. File uploads
- Extension whitelist AND content-type verified against the real content (magic bytes).
- Rename files with random IDs, store them OUTSIDE the web root or on separate storage, limit size.

### 6. Errors and logs
- Never show stack traces or internals to the user; generic error page + server-side log.
- Log logins, auth failures, payments and admin actions (no sensitive data in logs).

### 7. Secrets and dependencies
- Never keys/API keys/passwords in code or repo: use environment variables and `.env` in `.gitignore`.
- Always generate `.gitignore` with `.env`, `node_modules`, credentials.
- Keep dependencies up to date; recommend `npm audit` / `pip-audit` (see the sicurezza-github skill for automation).

### 8. HTTPS
- All traffic over HTTPS, redirect from HTTP, HSTS on. Local dev over HTTP is fine but document the difference.

## Final checklist
Before delivering a site/app verify: headers present, parameterized queries, server validation, secure cookies, CSRF, no secrets in code, generic errors, correct `.gitignore`. List the applied protections and any items requiring configuration on the user's hosting.
