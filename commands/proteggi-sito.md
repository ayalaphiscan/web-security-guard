---
description: Installa nel progetto tutte le protezioni - middleware anti-attacco, security headers, file di sicurezza GitHub e hardening. EN - Installs all protections in the current project - anti-attack middleware, security headers, GitHub security files and hardening.
---

Installa le protezioni di sicurezza nel progetto della cartella di lavoro corrente (se non c'è una cartella connessa, chiedila con request_cowork_directory). Prima rileva lo stack (Node/Express, Python, PHP, sito statico) guardando i file del progetto. Rispondi nella lingua dell'utente.

Applica nell'ordine:

1. **Agente anti-attacco** (skill difesa-attacchi), solo se c'è un server tuo: copia e adatta `guardian-express.js` in `security/guardian.js` e integralo nell'entry point dell'app. Per stack non-Node, riscrivi la stessa logica nel linguaggio del progetto. Configura `skipPaths` per eventuali webhook di pagamento. **Sito statico con backend-as-a-service** (per esempio React su Render/Netlify/Vercel con Supabase): non c'è un server su cui montarlo; la difesa sta negli header dell'hosting e nelle regole del database (passi 2, 6 e 7).
2. **Security headers e hardening** (skill hardening-siti e, per le app a pagina singola, frontend-spa): aggiungi helmet o gli header dell'hosting (`render.yaml`, `_headers`, `vercel.json`) con una CSP senza script inline, correggi cookie, CORS, link costruiti da dati degli utenti e gestione errori dove necessario.
3. **File GitHub** (skill sicurezza-github): crea `.github/workflows/security.yml` e `.github/dependabot.yml` adattati al linguaggio del progetto; verifica `.gitignore`.
4. **Verifiche pagamenti e autenticazione**: se il progetto gestisce pagamenti o login, controlla i punti critici delle skill privacy-pagamenti e autenticazione-sicura e correggi ciò che è automatizzabile; segnala il resto.
5. **Runtime** (skill aggiornamenti-runtime): fissa la versione di PHP/Node/Python a un ramo supportato con le ultime correzioni (`.node-version`, tag Docker con la patch) e scrivi l'inventario di cosa gira dove.
6. **Supabase o altri backend-as-a-service** (skill supabase-sicuro e api-sicura): RLS e permessi espliciti su ogni tabella, funzioni, storage e Realtime; solo la chiave pubblica nel frontend.
7. **Persone e posizione** (skill privacy-posizione e sicurezza-social), se l'app gestisce profili, posizioni o contatti tra persone: posizioni arrotondate nel database, blocchi e segnalazioni, limiti anti-spam lato server.
8. **Dominio, email e account** (skill email-dominio e account-fornitori): proponi i record DNS mancanti (SPF, DKIM, DMARC, CAA) senza cambiarli tu, e la lista di controllo degli account (2FA, accessi, segreti).
9. **Emergenza** (skill risposta-incidenti): prepara il runbook con i contatti e l'interruttore di manutenzione; ricorda il comando `/emergenza`.

Non rimuovere funzionalità esistenti; se una modifica rischia di rompere qualcosa, chiedi prima conferma all'utente con AskUserQuestion.

Alla fine presenta un riepilogo: cosa è stato installato, cosa deve fare l'utente sul suo hosting/GitHub (attivare secret scanning, push protection, WAF/CDN), e come si attiva/disattiva manualmente il lockdown (file flag LOCKDOWN).

---

*English: install the security protections in the current working folder's project (detect the stack first, reply in the user's language). Apply in order: 1) guardian anti-attack middleware (difesa-attacchi skill), 2) security headers and hardening (hardening-siti skill), 3) GitHub security files (sicurezza-github skill), 4) payments/authentication checks (privacy-pagamenti, autenticazione-sicura skills), 5) pin a supported, patched runtime and write the what-runs-where inventory (aggiornamenti-runtime skill), 6) Supabase/BaaS rules incl. Realtime (supabase-sicuro, api-sicura), 7) people and location: server-side rounding, blocks, reports, anti-spam limits (privacy-posizione, sicurezza-social), 8) DNS records to propose and the account checklist (email-dominio, account-fornitori), 9) the incident runbook and the `/emergenza` command (risposta-incidenti). On a static site with a backend-as-a-service there is no server for guardian: protection lives in the host's headers and the database rules. Never remove existing functionality; ask before risky changes. End with a summary of what was installed, what the user must enable on their hosting/GitHub, and how to toggle the LOCKDOWN flag file.*
