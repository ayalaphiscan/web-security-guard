---
description: Esegue un audit di sicurezza completo del progetto corrente e produce un report con problemi e correzioni. EN - Runs a full security audit of the current project and produces a report with findings and fixes.
---

Esegui un audit di sicurezza del progetto nella cartella di lavoro corrente (se non c'è una cartella connessa, chiedila con request_cowork_directory; in Claude Code lavora nella cartella corrente). Rispondi nella lingua dell'utente.

Analizza il codice cercando, in ordine di gravità:

1. **Segreti nel codice**: API key, password, token, chiavi private hardcoded o in file committati (controlla anche che `.env` sia in `.gitignore`).
2. **Injection**: query SQL costruite con concatenazione, input utente in comandi shell, `eval`, percorsi file da input.
3. **XSS e frontend**: input utente inserito in HTML senza escaping (`innerHTML`, `dangerouslySetInnerHTML`, popup delle mappe con `setHTML`, template senza autoescape), link costruiti da dati degli utenti (`javascript:`), CSP con `unsafe-inline` o domini jolly, segreti nel bundle e nelle variabili `VITE_*`, source map pubbliche (skill frontend-spa).
4. **Autenticazione**: password non hashate o con hash deboli (MD5/SHA1), assenza di rate limiting sul login, sessioni/cookie senza flag di sicurezza, mancanza di verifica email o 2FA dove appropriato (confronta con la skill autenticazione-sicura).
5. **Pagamenti**: dati carta salvati o loggati, webhook senza verifica firma, prezzi presi dal client (confronta con la skill privacy-pagamenti).
6. **Configurazione**: security headers mancanti, CORS aperto, errori che espongono stack trace, HTTP senza redirect a HTTPS (confronta con la skill hardening-siti).
7. **Dipendenze**: esegui `npm audit` o `pip-audit` se disponibili nel sandbox.
8. **Runtime**: versione di PHP/Node/Python in Dockerfile (`FROM`), `.node-version`/`.nvmrc`, `composer.json`, workflow CI e configurazione dell'hosting. Confrontala con gli ultimi rilasci di sicurezza (skill aggiornamenti-runtime). Un ramo fuori supporto (Node 20, PHP 8.1 o precedenti) o una versione senza le ultime correzioni è **Alta**; se è esposto a internet ed esiste un avviso critico, **Critica**.
9. **Backend-as-a-service** (Supabase, Firebase): RLS su ogni tabella, permessi espliciti, funzioni `SECURITY DEFINER`, policy dello storage, Realtime, chiavi nel frontend (skill supabase-sicuro; per un audit completo del database usa `/audit-supabase`).
10. **API**: accesso agli oggetti di altri utenti con un secondo token, campi privilegiati scrivibili, RPC senza controllo di chi chiama, limiti di frequenza (skill api-sicura).
11. **Posizione e dati sensibili**: posizioni esatte salvate o restituite, distanze precise, GPS nelle foto, dati dell'art. 9 senza consenso esplicito o visibili agli sconosciuti, conteggi che rivelano chi è chi (skill privacy-posizione).
12. **Sicurezza social** (se l'app mette in contatto persone): blocchi applicati nel database, segnalazioni, limiti anti-spam lato server, enumerazione degli utenti (skill sicurezza-social).
13. **Dominio ed email**: SPF, DKIM, DMARC, CAA, sottodomini che puntano a servizi rimossi (skill email-dominio; per il DNS proponi i record, non cambiarli).
14. **Repo GitHub e account**: workflow di sicurezza, Dependabot, action bloccate al commit, 2FA e accessi dei fornitori (skill sicurezza-github, account-fornitori).

Produci un report con: riepilogo (numero problemi per gravità Critica/Alta/Media/Bassa), per ogni problema il file e la riga, perché è pericoloso (in linguaggio semplice), e la correzione concreta. Salva il report come `security-audit.md` negli outputs e presentalo con present_files.

Alla fine chiedi all'utente se vuole che applichi subito le correzioni (in tal caso applica le skill di questo plugin).

---

*English: run a security audit of the current working folder's project (reply in the user's language). Scan in order of severity: hardcoded secrets, injection (SQL/shell/eval/paths), XSS, authentication weaknesses, payment-data handling, front-end/SPA (XSS sinks incl. map popups, unsafe links, CSP, secrets in the bundle, source maps), configuration (headers, CORS, stack traces, HTTPS), vulnerable dependencies (`npm audit`/`pip-audit`), runtime versions (PHP/Node/Python in Dockerfile, `.node-version`, CI, hosting) against the latest security releases, backend-as-a-service rules (Supabase RLS, grants, storage, Realtime, keys; `/audit-supabase` for a full database audit), API authorization and rate limits, location and art. 9 data, social safety (blocks, reports, anti-spam, enumeration), domain and email (SPF/DKIM/DMARC/CAA), GitHub workflows and provider accounts. Produce a report (counts by Critical/High/Medium/Low, file and line per finding, plain-language risk and concrete fix), save it as `security-audit.md` in outputs and present it. Finally ask the user whether to apply the fixes right away using this plugin's skills.*
