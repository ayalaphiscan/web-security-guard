---
description: Esegue un audit di sicurezza completo del progetto corrente e produce un report con problemi e correzioni. EN - Runs a full security audit of the current project and produces a report with findings and fixes.
---

Esegui un audit di sicurezza del progetto nella cartella di lavoro corrente (se non c'è una cartella connessa, chiedila con request_cowork_directory). Rispondi nella lingua dell'utente.

Analizza il codice cercando, in ordine di gravità:

1. **Segreti nel codice**: API key, password, token, chiavi private hardcoded o in file committati (controlla anche che `.env` sia in `.gitignore`).
2. **Injection**: query SQL costruite con concatenazione, input utente in comandi shell, `eval`, percorsi file da input.
3. **XSS**: input utente inserito in HTML senza escaping (`innerHTML`, template senza autoescape).
4. **Autenticazione**: password non hashate o con hash deboli (MD5/SHA1), assenza di rate limiting sul login, sessioni/cookie senza flag di sicurezza, mancanza di verifica email o 2FA dove appropriato (confronta con la skill autenticazione-sicura).
5. **Pagamenti**: dati carta salvati o loggati, webhook senza verifica firma, prezzi presi dal client (confronta con la skill privacy-pagamenti).
6. **Configurazione**: security headers mancanti, CORS aperto, errori che espongono stack trace, HTTP senza redirect a HTTPS (confronta con la skill hardening-siti).
7. **Dipendenze**: esegui `npm audit` o `pip-audit` se disponibili nel sandbox.
8. **Repo GitHub**: presenza di workflow di sicurezza e dependabot (skill sicurezza-github).

Produci un report con: riepilogo (numero problemi per gravità Critica/Alta/Media/Bassa), per ogni problema il file e la riga, perché è pericoloso (in linguaggio semplice), e la correzione concreta. Salva il report come `security-audit.md` negli outputs e presentalo con present_files.

Alla fine chiedi all'utente se vuole che applichi subito le correzioni (in tal caso applica le skill di questo plugin).

---

*English: run a security audit of the current working folder's project (reply in the user's language). Scan in order of severity: hardcoded secrets, injection (SQL/shell/eval/paths), XSS, authentication weaknesses, payment-data handling, configuration (headers, CORS, stack traces, HTTPS), vulnerable dependencies (`npm audit`/`pip-audit`), GitHub security workflows. Produce a report (counts by Critical/High/Medium/Low, file and line per finding, plain-language risk and concrete fix), save it as `security-audit.md` in outputs and present it. Finally ask the user whether to apply the fixes right away using this plugin's skills.*
