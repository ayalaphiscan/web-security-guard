---
name: risposta-incidenti
description: Risposta agli incidenti di sicurezza per team piccoli con servizi gestiti - runbook preparato prima, interruttore d'emergenza, revoca delle sessioni, rotazione delle chiavi, prove, ripristino, notifica GDPR entro 72 ore, post-mortem. Trigger - "incidente", "attacco in corso", "violazione dei dati", "data breach", "chiave esposta", "account compromesso", "lockdown". EN - Security incident response for small teams on managed services - a runbook prepared in advance, kill switch, session revocation, key rotation, evidence, recovery, GDPR 72-hour notification, post-mortem. Triggers - "incident", "ongoing attack", "data breach", "leaked key", "compromised account", "lockdown", "emergency".
---

# Risposta agli incidenti · Incident Response

> 🇮🇹 Versione italiana qui sotto · 🇬🇧 [English version below](#incident-response-english)

Un incidente si gestisce bene solo se è stato preparato prima: in emergenza non c'è tempo per cercare password, capire chi decide o scoprire che il backup non c'è. Per un team piccolo con servizi gestiti (frontend statico, Supabase per database, Auth, Storage e Realtime, nessun server proprio) le leve sono poche e precise: impostazioni delle console, SQL, chiavi. Questa skill dice quali preparare e in che ordine usarle. Prevenzione: skill hardening-siti, supabase-sicuro, frontend-spa, api-sicura; account dei servizi: account-fornitori; email e dominio: email-dominio; persone in pericolo: sicurezza-social; server propri: aggiornamenti-runtime e architettura-fortezza.

## Regole obbligatorie

### 1. Preparare prima
- **Runbook** scritto ora (modello in fondo) in `docs/INCIDENTI.md`, con una copia fuori dalla repo (gestore di password o stampa): se l'account GitHub è compromesso non lo si legge. Rivederlo ogni sei mesi e dopo ogni incidente.
- **Chi decide**: un responsabile dell'incidente e un sostituto, liberi di attivare la manutenzione senza chiedere a nessuno. Notifica al Garante, avvisi agli utenti e ripristini li decide il titolare del trattamento, nominato nel runbook. Durante l'incidente una persona agisce e un'altra scrive la cronologia con gli orari.
- **Accessi**: per ogni console (database, hosting, DNS e registrar, GitHub, email, pagamenti, store) almeno due amministratori, 2FA con app o passkey, codici di recupero offline (skill account-fornitori).
- **Backup verificati**: sapere cosa include il piano (backup giornalieri, PITR come extra a pagamento) e aggiungere un dump proprio, cifrato, fuori dal fornitore: `supabase db dump -f roles.sql --role-only`, `supabase db dump -f schema.sql`, `supabase db dump -f data.sql --data-only`. I backup del database di Supabase **non** contengono i file di Storage: copiarli a parte. Provare un ripristino completo ogni trimestre e annotare la data.
- **Log**: sapere quanti giorni il piano conserva i log (sui piani economici pochi) e, se non bastano, usare un log drain dove il piano lo prevede. Per le azioni sensibili (moderatori, amministratori, cambi di ruolo) un registro in `private.audit_log`: chi, cosa, quale riga, quando. Mai password, token o posizioni esatte nei log (skill privacy-posizione).
- **Pronti in anticipo**: interruttore di emergenza (punto 3) provato, testi di manutenzione e di avviso agli utenti in italiano e inglese, schema della notifica al Garante, registro delle violazioni (punto 10).

### 2. Segnali da guardare
- **Advisor** di Supabase (Security e Performance): un avviso nuovo, per esempio una tabella senza RLS o una funzione esposta, è un incidente possibile finché non è chiuso.
- **Iscrizioni anomale**: picchi orari, indirizzi simili, stessa rete: `select date_trunc('hour', created_at) as ora, count(*) from auth.users where created_at > now() - interval '2 days' group by 1 order by 1 desc;`
- **Errori e traffico**: picchi di 401, 403, 429 o 5xx nei log dell'API, uscita dati (egress) in salita nella pagina Usage. Spesso è scraping o enumerazione in corso.
- **Segnalazioni degli utenti** ("vedo chi mi ha bloccato", "il mio account ha scritto messaggi non miei"): un indirizzo di sicurezza letto ogni giorno, risposta entro 24 ore.
- **Segreti esposti**: avvisi di GitHub secret scanning e push protection, email di un fornitore che ha trovato una sua chiave in un repository pubblico (a volte l'ha già disattivata), Dependabot critico (skill sicurezza-github).
- **Cambi non spiegati**: membri nuovi nelle console, chiavi API create, ruoli alti assegnati, policy o funzioni cambiate fuori dalle migrazioni, costi in salita.

### 3. Interruttore di emergenza, senza deploy
Un sito statico vive nel browser di ognuno: serve un interruttore che si gira con una riga SQL, senza build. Con un server proprio, la modalità lockdown della skill difesa-attacchi fa lo stesso.
```sql
create table public.app_status (id int primary key default 1 check (id = 1),
  maintenance boolean not null default false, read_only boolean not null default false, message text);
alter table public.app_status enable row level security;
create policy "stato leggibile" on public.app_status for select to anon, authenticated using (true);
grant select on public.app_status to anon, authenticated;  -- nessuna scrittura: si cambia solo dal SQL Editor
insert into public.app_status default values;
-- su ogni tabella scrivibile (anche storage.objects); per update e delete la stessa condizione in using
create policy "sola lettura in emergenza" on public.messages as restrictive for insert to authenticated
  with check (not (select read_only from public.app_status where id = 1));
-- emergenza: update public.app_status set maintenance = true, message = 'Manutenzione in corso';
```
- Nell'app, all'avvio e ogni pochi minuti: `supabase.from('app_status').select('maintenance, message').single()`. Con `maintenance` vero, o se la lettura fallisce, mostrare solo la pagina di manutenzione.
- `maintenance` protegge le persone; `read_only` ferma le scritture dirette sulle tabelle, anche via API. Le funzioni `security definer` e i trigger del proprietario passano sopra la RLS: ognuna deve cominciare con un controllo, altrimenti in sola lettura continua a scrivere:
```sql
create or replace function private.assert_writable() returns void language plpgsql stable set search_path = '' as $$
begin
  if (select read_only from public.app_status where id = 1) then
    raise sqlstate 'PGRST' using message = '{"code":"read_only","message":"Sola lettura"}', detail = '{"status":503}';
  end if;
end $$;
-- prima riga di ogni funzione security definer che scrive: perform private.assert_writable();
```
- Broadcast e Presence di Realtime non passano dalle policy delle tabelle: nei canali privati la stessa condizione va nelle policy di `realtime.messages`.
- Chiusura totale, solo nel caso peggiore, con una migrazione di emergenza: `revoke all on all tables in schema public from anon, authenticated;` e `revoke execute on all functions in schema public from public, anon, authenticated;`. Per riaprire servono i grant esatti: tenerli pronti in un file.
- Sull'hosting: sapere già come tornare al deploy precedente (rollback) e come servire una pagina di manutenzione dal DNS o dal CDN.

### 4. La prima ora, passo per passo
1. **Minuto 0**: aprire il documento dell'incidente, scrivere l'ora (T0) e cosa si sa; da qui ogni azione con l'orario. Chiamare il responsabile. Non cancellare nulla.
2. **Entro 10 minuti**: capire quali dati, quali persone, se l'attacco è in corso; scegliere la gravità con la tabella sotto (nel dubbio, quella più alta).
3. **Contenere** con le leve del punto 5, partendo da quella che ferma il danno più in fretta.
4. **Conservare le prove** (punto 6) prima che i log scadano.
5. **Decidere sul GDPR**: se sono coinvolti dati personali, le 72 ore corrono dalla consapevolezza (punto 10). Scriverlo nel documento.
6. **Avvisare** il titolare e, se la falla sembra del fornitore, il suo supporto. Fissare l'aggiornamento successivo (per esempio ogni ora).

### 5. Leve di contenimento in Supabase
- **Iscrizioni chiuse**: Authentication → Sign In / Providers → "Allow new users to sign up" spento (`disable_signup` nella Management API). Captcha attiva prima di riaprire.
- **Permesso pericoloso revocato** con una migrazione di emergenza, salvata anche in `supabase/migrations/` perché il deploy successivo non lo rimetta: `revoke select on public.profiles from anon;`, `revoke execute on function public.export_contacts() from public, anon, authenticated;`.
- **Account abusivo bloccato, non cancellato** (le sue righe sono prove):
```sql
-- prima le prove: le sessioni dicono IP, browser e orari usati
create table private.incident_sessions_<data> as select * from auth.sessions where user_id = '<uuid>';
create table private.incident_refresh_<data> as select * from auth.refresh_tokens where user_id = '<uuid>'::text;
update auth.users set banned_until = now() + interval '100 years' where id = '<uuid>';
delete from auth.sessions where user_id = '<uuid>';  -- i refresh token cadono con le sessioni
```
- Il token di accesso già emesso resta valido fino alla scadenza (1 ora di default). Per un taglio immediato sulle tabelle più delicate, le policy possono chiedere che la sessione esista ancora: `exists (select 1 from auth.sessions where id = ((select auth.jwt()) ->> 'session_id')::uuid)`.
- Da uno script con la chiave secret, lo stesso blocco: `supabase.auth.admin.updateUserById(id, { ban_duration: '876000h' })`.
- **Tutti disconnessi**: prima la copia di `auth.sessions` e `auth.refresh_tokens` come sopra, poi `delete from auth.sessions;`. I token di accesso già emessi restano validi fino alla scadenza (di default 1 ora). Per tagliarli subito: con le chiavi di firma asimmetriche, ruotare sulla chiave di riserva e revocare la precedente; con il vecchio JWT secret, cambiarlo (invalida anche le chiavi legacy `anon` e `service_role`: aggiornare il frontend).
- **Chiave secret esposta**: crearne una nuova in Settings → API Keys, aggiornarla dove serve (segreti delle Edge Functions, script), poi eliminare la vecchia. Una chiave `service_role` legacy (JWT) non si ruota da sola: si disattivano le chiavi legacy in Settings → API Keys, dopo il passaggio a publishable/secret, oppure si ruota il JWT secret. La publishable è pubblica per natura: cambiarla rallenta uno scraping per poco, la difesa vera resta la RLS.

### 6. Conservare le prove
- Esportare subito dal Logs Explorer i log della finestra dell'incidente (API, Auth, Storage, Edge Functions, Realtime) e salvarli in file: con pochi giorni di conservazione è il primo lavoro dopo il contenimento.
- Fotografare lo stato: dump di schema e dati, policy e grant (`pg_policies`, `information_schema.role_table_grants`), schermate di Advisor e impostazioni, deploy e commit in produzione, audit log di GitHub.
- Bloccare invece di cancellare: account sospesi, righe e file sospetti marcati o spostati. Le prove contengono dati personali: cartella cifrata, accesso al solo team dell'incidente, cancellazione a caso chiuso.

### 7. Eliminare la causa e ruotare i segreti
- Correggere con il flusso normale, accelerato: migrazione o commit, revisione di una seconda persona, deploy. Aggiungere il test che avrebbe trovato il problema (per la RLS: prove come utenti diversi, skill supabase-sicuro punto 7).
- Ruotare ogni segreto che può essere stato visto, non solo quello sospetto: chiave secret o `service_role`, password del database, segreti delle Edge Functions, chiavi di email, mappe e pagamenti, firme dei webhook, client secret OAuth, variabili dell'hosting, token GitHub e chiavi di deploy, token personali di Supabase (CLI, MCP). Un segreto finito in un commit resta nella cronologia: si ruota.
- Account del team violati: nuove password e 2FA, sessioni chiuse, membri e app OAuth sconosciuti rimossi, controllo di ciò che hanno creato (chiavi, webhook, inoltri email).
- Cercare ciò che l'attaccante può aver lasciato: utenti con ruoli alti, policy cambiate, bucket resi pubblici, webhook verso indirizzi sconosciuti, funzioni `security definer` nuove: `select p.oid::regprocedure from pg_proc p join pg_namespace n on n.oid = p.pronamespace where p.prosecdef and n.nspname in ('public', 'private');`. Poi lavori pianificati (`select * from cron.job;`), trigger non interni (`select tgname, tgrelid::regclass from pg_trigger where not tgisinternal;`), event trigger (`pg_event_trigger`), ruoli che possono accedere (`select rolname from pg_roles where rolcanlogin;`), tabelle pubblicate su Realtime (`pg_publication_tables`), bucket pubblici (`select id from storage.buckets where public;`).

### 8. Ripristinare
- Dati cambiati o cancellati: scegliere dalla cronologia un punto precedente all'attacco (PITR o backup). Un ripristino di Supabase sostituisce l'intero database e perde le scritture legittime successive: quando si può, ripristinare in un progetto o database separato e ricopiare solo le righe alterate.
- File di Storage toccati: ricaricarli dalla copia a parte.
- Verificare prima di riaprire: conteggi e campioni delle tabelle principali, Advisor puliti, test end-to-end e prove RLS verdi. Riaprire per gradi (sola lettura, scritture, iscrizioni) guardando log ed errori.

### 9. Comunicare
- Una sola persona parla all'esterno. Ogni messaggio dice cosa è successo, quali dati, cosa è stato fatto, cosa deve fare la persona (cambiare la password se usata altrove, diffidare di chi chiede codici o soldi), a chi scrivere. Niente ipotesi né minimizzazioni; aggiornare quando si sa di più.
- Avvisare i partner coinvolti (organizzatori di eventi, chi usa la vostra API) nei tempi dei contratti.
- Reati (accesso abusivo, ricatto, minacce): denuncia, in Italia alla Polizia Postale, con le prove conservate. Persone in pericolo: skill sicurezza-social.

### 10. Obblighi di legge nell'UE
- Violazione di dati personali (art. 4(12) GDPR): distruzione, perdita, modifica, divulgazione o accesso non autorizzati, anche per errore. Una falla senza accesso dimostrato non lo è ancora; se i log non permettono di escludere l'accesso, trattarla come violazione.
- **Autorità di controllo** (in Italia il Garante, con la procedura online sul suo sito): senza ingiustificato ritardo e, ove possibile, entro 72 ore dalla consapevolezza (art. 33(1)), salvo che il rischio per le persone sia improbabile; oltre le 72 ore, con i motivi del ritardo. Contenuto (art. 33(3)): natura della violazione, categorie e numero approssimativo di persone e record, contatto del DPO o referente, conseguenze probabili, misure prese o previste. Si può notificare per fasi (art. 33(4)): meglio una prima notifica incompleta in tempo.
- **Persone coinvolte** (art. 34): senza ingiustificato ritardo se il rischio è elevato, in linguaggio semplice. Non serve se i dati erano cifrati e illeggibili o se le misure prese hanno tolto il rischio elevato; con sforzo sproporzionato basta un avviso pubblico (art. 34(3)). Posizioni, chat private e dati dell'art. 9 (orientamento sessuale, opinioni politiche, convinzioni religiose) rendono il rischio elevato quasi sempre.
- **Registro delle violazioni** (art. 33(5)): ogni violazione, anche non notificata, con fatti, effetti, rimedi e il motivo della scelta. Un fornitore che tratta dati per voi deve avvisarvi senza ingiustificato ritardo (art. 33(2)): verificarlo nel contratto (DPA).
- **NIS2** (Direttiva UE 2022/2555; in Italia D.Lgs. 138/2024, autorità ACN): solo per soggetti medi e grandi dei settori elencati, tra cui le piattaforme di social network; le piccole imprese ne sono di norma fuori. Se si applica, per gli incidenti significativi: preallarme entro 24 ore, notifica entro 72 ore, relazione finale entro un mese al CSIRT (CSIRT Italia), in aggiunta al GDPR.
- Riferimenti: Linee guida EDPB 9/2022 sulla notifica e 01/2021 con esempi pratici. Verificare i casi dubbi con un legale.

### 11. Post-mortem senza colpe
- Entro una settimana dalla chiusura: cronologia con gli orari, causa tecnica, perché nessun controllo l'ha fermata, cosa ha funzionato e cosa è mancato. Si cercano difetti nei processi, non colpevoli.
- Ogni azione con responsabile e data, tracciata come issue: test o controllo automatico, regola nuova in una skill, runbook aggiornato. Chiudere la voce nel registro delle violazioni con i rimedi.

## Tabella di gravità
| Gravità | Esempi | Azioni |
|---|---|---|
| 1 Critica | dati di altri letti o modificati; chiave secret pubblicata; account presi; posizioni o dati dell'art. 9 esposti; SOS guasto | subito: manutenzione o sola lettura, revoca, rotazione, tutti disconnessi; prove; 72 ore GDPR; avviso alle persone; tutto il team |
| 2 Alta | falla aperta senza segni d'uso; un account preso; ondata di bot o spam; scraping in corso | entro ore: correzione mirata, iscrizioni chiuse o captcha, ban; log controllati per escludere l'accesso; voce nel registro |
| 3 Media | avviso nuovo dell'Advisor; dipendenza vulnerabile non raggiungibile; tentativi falliti | entro giorni: PR normale con il test che lo copre |
| 4 Bassa | segnalazione senza effetto, falso allarme | annotare e rispondere a chi ha segnalato |

## Modello di runbook
```markdown
# Runbook incidenti — <progetto>  (copia offline in <dove>; rivisto il <data>)
Responsabile: <nome, telefono> · Sostituto: <nome, telefono> · Titolare/DPO: <nome, email>
Canale dell'incidente: <chat o telefono> · Documento dell'incidente: <link>
Console (2 admin, 2FA): Supabase <ref> · hosting <servizio> · DNS/registrar <…> · GitHub <org> · email <…> · pagamenti <…>
Supporto: Supabase <link> · hosting <link> · Garante: procedura online di notifica
Backup: piano <…> · PITR <sì/no> · dump proprio <dove> · file Storage <dove> · ultimo ripristino provato <data>
Log: conservazione <giorni> · export <come>
Manutenzione: update public.app_status set maintenance = true, message = '<testo>';
Sola lettura: update public.app_status set read_only = true;
Iscrizioni: Authentication → Sign In / Providers → Allow new users to sign up = off
Tutti fuori: delete from auth.sessions; + rotazione della chiave di firma JWT
Rollback del frontend: <come, sull'hosting> · Grant per riaprire: <file>
Segreti da ruotare (dove): <elenco>
Prima ora: T0 → responsabile → gravità → contenere → prove → decisione GDPR → avvisi
Testi pronti: <manutenzione, email agli utenti, notifica al Garante> · Registro violazioni: <link>
```

## Limiti da comunicare
Questa skill non sostituisce un legale né un'azienda di analisi forense: negli incidenti gravi coinvolgerli presto. Le 72 ore corrono dalla consapevolezza, non dalla fine delle indagini. L'interruttore nell'interfaccia protegge le persone, non i dati: la chiusura vera è nel database. Ruotare le chiavi non cancella ciò che è già stato copiato.

---

# Incident Response (English)

An incident is handled well only if it was prepared beforehand: in an emergency there is no time to hunt for passwords, work out who decides or find out the backup is missing. For a small team on managed services (static front-end, Supabase for database, Auth, Storage and Realtime, no own server) the levers are few and precise: console settings, SQL, keys. This skill says which to prepare and in what order to use them. Prevention: hardening-siti, supabase-sicuro, frontend-spa, api-sicura skills; service accounts: account-fornitori; email and domain: email-dominio; people in danger: sicurezza-social; own servers: aggiornamenti-runtime and architettura-fortezza.

## Mandatory rules

### 1. Prepare beforehand
- **Runbook** written now (template at the end) in `docs/INCIDENTI.md`, with a copy outside the repo (password manager or paper): if the GitHub account is compromised you cannot read it. Review it every six months and after every incident.
- **Who decides**: an incident lead and a deputy, free to turn on maintenance without asking anyone. Notifying the authority, telling users and restoring are decided by the data controller, named in the runbook. During the incident one person acts and another writes the timeline with times.
- **Access**: for every console (database, hosting, DNS and registrar, GitHub, email, payments, app stores) at least two admins, 2FA with an app or passkey, recovery codes kept offline (account-fornitori skill).
- **Verified backups**: know what the plan includes (daily backups, PITR as a paid add-on) and add your own encrypted dump outside the provider: `supabase db dump -f roles.sql --role-only`, `supabase db dump -f schema.sql`, `supabase db dump -f data.sql --data-only`. Supabase database backups do **not** contain Storage files: copy them separately. Test a full restore every quarter and note the date.
- **Logs**: know how many days the plan keeps logs (few on the cheaper plans) and, if that is not enough, use a log drain where the plan offers one. For sensitive actions (moderators, admins, role changes) a log in `private.audit_log`: who, what, which row, when. Never passwords, tokens or exact locations in logs (privacy-posizione skill).
- **Ready in advance**: the emergency switch (rule 3) tested, maintenance and user notice texts in Italian and English, an outline of the authority notification, the breach register (rule 10).

### 2. Signals to watch
- Supabase **Advisors** (Security and Performance): a new warning, e.g. a table without RLS or an exposed function, is a possible incident until it is closed.
- **Unusual sign-ups**: hourly spikes, similar addresses, same network: `select date_trunc('hour', created_at) as hour, count(*) from auth.users where created_at > now() - interval '2 days' group by 1 order by 1 desc;`
- **Errors and traffic**: spikes of 401, 403, 429 or 5xx in the API logs, rising egress on the Usage page. Often scraping or enumeration in progress.
- **User reports** ("I can see someone who blocked me", "my account sent messages I didn't write"): a security address read daily, answered within 24 hours.
- **Exposed secrets**: GitHub secret scanning and push protection alerts, an email from a provider that found one of its keys in a public repository (sometimes already disabled), critical Dependabot alerts (sicurezza-github skill).
- **Unexplained changes**: new console members, API keys created, high roles granted, policies or functions changed outside migrations, rising costs.

### 3. Emergency switch, no deploy
A static site lives in everyone's browser: you need a switch flipped with one SQL line, no build. With your own server, the lockdown mode of the difesa-attacchi skill does the same.
```sql
create table public.app_status (id int primary key default 1 check (id = 1),
  maintenance boolean not null default false, read_only boolean not null default false, message text);
alter table public.app_status enable row level security;
create policy "status readable" on public.app_status for select to anon, authenticated using (true);
grant select on public.app_status to anon, authenticated;  -- no writes: changed only from the SQL Editor
insert into public.app_status default values;
-- on every writable table (storage.objects too); for update and delete the same condition in using
create policy "read-only in emergency" on public.messages as restrictive for insert to authenticated
  with check (not (select read_only from public.app_status where id = 1));
-- emergency: update public.app_status set maintenance = true, message = 'Maintenance in progress';
```
- In the app, at start-up and every few minutes: `supabase.from('app_status').select('maintenance, message').single()`. When `maintenance` is true, or the read fails, show only the maintenance page.
- `maintenance` protects people; `read_only` stops direct writes to the tables, including through the API. `security definer` functions and owner triggers bypass RLS: each one must start with a check, or it keeps writing in read-only mode:
```sql
create or replace function private.assert_writable() returns void language plpgsql stable set search_path = '' as $$
begin
  if (select read_only from public.app_status where id = 1) then
    raise sqlstate 'PGRST' using message = '{"code":"read_only","message":"Read-only"}', detail = '{"status":503}';
  end if;
end $$;
-- first line of every security definer function that writes: perform private.assert_writable();
```
- Realtime Broadcast and Presence do not go through table policies: for private channels the same condition goes in the `realtime.messages` policies.
- Full shutdown, only in the worst case, with an emergency migration: `revoke all on all tables in schema public from anon, authenticated;` and `revoke execute on all functions in schema public from public, anon, authenticated;`. Reopening needs the exact grants: keep them ready in a file.
- On the hosting: know already how to go back to the previous deploy (rollback) and how to serve a maintenance page from DNS or the CDN.

### 4. The first hour, step by step
1. **Minute 0**: open the incident document, write the time (T0) and what is known; from here every action gets a time. Call the lead. Delete nothing.
2. **Within 10 minutes**: work out which data, which people, whether the attack is ongoing; pick the severity from the table below (when in doubt, the higher one).
3. **Contain** with the levers of rule 5, starting with the one that stops the damage fastest.
4. **Preserve evidence** (rule 6) before the logs expire.
5. **Decide on GDPR**: if personal data is involved, the 72 hours run from awareness (rule 10). Write it in the document.
6. **Notify** the controller and, if the flaw looks like the provider's, its support. Set the next update (e.g. hourly).

### 5. Containment levers in Supabase
- **Sign-ups closed**: Authentication → Sign In / Providers → "Allow new users to sign up" off (`disable_signup` in the Management API). Captcha on before reopening.
- **Dangerous grant revoked** with an emergency migration, also saved in `supabase/migrations/` so the next deploy does not put it back: `revoke select on public.profiles from anon;`, `revoke execute on function public.export_contacts() from public, anon, authenticated;`.
- **Abusive account blocked, not deleted** (its rows are evidence):
```sql
-- evidence first: sessions record the IPs, browsers and times used
create table private.incident_sessions_<date> as select * from auth.sessions where user_id = '<uuid>';
create table private.incident_refresh_<date> as select * from auth.refresh_tokens where user_id = '<uuid>'::text;
update auth.users set banned_until = now() + interval '100 years' where id = '<uuid>';
delete from auth.sessions where user_id = '<uuid>';  -- refresh tokens go with the sessions
```
- An access token already issued stays valid until it expires (1 hour by default). For an immediate cut on the most sensitive tables, policies can require the session to still exist: `exists (select 1 from auth.sessions where id = ((select auth.jwt()) ->> 'session_id')::uuid)`.
- From a script with the secret key, the same block: `supabase.auth.admin.updateUserById(id, { ban_duration: '876000h' })`.
- **Everyone signed out**: first copy `auth.sessions` and `auth.refresh_tokens` as above, then `delete from auth.sessions;`. Access tokens already issued stay valid until they expire (1 hour by default). To cut them at once: with asymmetric signing keys, rotate to the standby key and revoke the previous one; with the legacy JWT secret, change it (this also invalidates the legacy `anon` and `service_role` keys: update the front-end).
- **Secret key exposed**: create a new one in Settings → API Keys, update it wherever it is used (Edge Function secrets, scripts), then delete the old one. A legacy `service_role` key (JWT) cannot be rotated on its own: disable the legacy keys in Settings → API Keys, after moving to publishable/secret, or rotate the JWT secret. The publishable key is public by nature: changing it slows scraping for a short while, the real defense remains RLS.

### 6. Preserve evidence
- Export from the Logs Explorer at once the logs of the incident window (API, Auth, Storage, Edge Functions, Realtime) and save them to files: with only a few days of retention this is the first job after containment.
- Snapshot the state: schema and data dump, policies and grants (`pg_policies`, `information_schema.role_table_grants`), screenshots of Advisors and settings, the deploy and commit in production, the GitHub audit log.
- Block instead of deleting: accounts suspended, suspicious rows and files flagged or moved. Evidence contains personal data: an encrypted folder, access for the incident team only, deletion once the case is closed.

### 7. Eradicate and rotate secrets
- Fix through the normal flow, sped up: migration or commit, review by a second person, deploy. Add the test that would have caught the problem (for RLS: tests as different users, supabase-sicuro skill, rule 7).
- Rotate every secret that may have been seen, not only the suspect one: secret or `service_role` key, database password, Edge Function secrets, email, maps and payment keys, webhook signing secrets, OAuth client secrets, hosting variables, GitHub tokens and deploy keys, Supabase personal access tokens (CLI, MCP). A secret that landed in a commit stays in the history: rotate it.
- Team accounts breached: new passwords and 2FA, sessions closed, unknown members and OAuth apps removed, check what they created (keys, webhooks, email forwarding).
- Look for what the attacker may have left: users with high roles, changed policies, buckets made public, webhooks to unknown addresses, new `security definer` functions: `select p.oid::regprocedure from pg_proc p join pg_namespace n on n.oid = p.pronamespace where p.prosecdef and n.nspname in ('public', 'private');`. Then scheduled jobs (`select * from cron.job;`), non-internal triggers (`select tgname, tgrelid::regclass from pg_trigger where not tgisinternal;`), event triggers (`pg_event_trigger`), roles that can log in (`select rolname from pg_roles where rolcanlogin;`), tables published to Realtime (`pg_publication_tables`), public buckets (`select id from storage.buckets where public;`).

### 8. Recover
- Data altered or deleted: pick from the timeline a point before the attack (PITR or backup). A Supabase restore replaces the whole database and loses the legitimate writes made since: when possible, restore into a separate project or database and copy back only the altered rows.
- Storage files touched: re-upload them from the separate copy.
- Verify before reopening: counts and samples of the main tables, clean Advisors, green end-to-end tests and RLS tests. Reopen in stages (read-only, writes, sign-ups) while watching logs and errors.

### 9. Communicate
- Only one person speaks externally. Every message says what happened, which data, what was done, what the person should do (change the password if reused elsewhere, distrust anyone asking for codes or money), whom to write to. No guesses or downplaying; update when more is known.
- Notify the partners involved (event organizers, users of your API) within the contractual deadlines.
- Crimes (unauthorized access, blackmail, threats): report to the police (in Italy the Polizia Postale), handing over the preserved evidence. People in danger: sicurezza-social skill.

### 10. Legal duties in the EU
- Personal data breach (GDPR art. 4(12)): unauthorized or accidental destruction, loss, alteration, disclosure of, or access to personal data. A flaw with no proven access is not one yet; if the logs cannot rule out access, treat it as a breach.
- **Supervisory authority** (in Italy the Garante, through the online procedure on its website): without undue delay and, where feasible, within 72 hours of awareness (art. 33(1)), unless the breach is unlikely to result in a risk to people; after 72 hours, with the reasons for the delay. Content (art. 33(3)): nature of the breach, categories and approximate number of people and records, DPO or contact point, likely consequences, measures taken or proposed. You may notify in phases (art. 33(4)): an incomplete first notification on time is better.
- **Affected people** (art. 34): without undue delay when the risk is high, in plain language. Not needed if the data was encrypted and unintelligible or if later measures removed the high risk; with disproportionate effort a public notice is enough (art. 34(3)). Locations, private chats and art. 9 data (sexual orientation, political opinions, religious beliefs) almost always make the risk high.
- **Breach register** (art. 33(5)): every breach, notified or not, with facts, effects, remedies and the reason for the decision. A provider processing data for you must tell you without undue delay (art. 33(2)): check it in the contract (DPA).
- **NIS2** (Directive (EU) 2022/2555; in Italy Legislative Decree 138/2024, authority ACN): only for medium and large entities in the listed sectors, including social networking platforms; small businesses are normally out of scope. If it applies, for significant incidents: early warning within 24 hours, notification within 72 hours, final report within one month to the CSIRT (CSIRT Italia), on top of GDPR.
- References: EDPB Guidelines 9/2022 on notification and 01/2021 with practical examples. Check doubtful cases with a lawyer.

### 11. Blameless post-mortem
- Within a week of closing: timeline with times, technical cause, why no control stopped it, what worked and what was missing. Look for process gaps, not culprits.
- Every action with an owner and a date, tracked as an issue: an automatic test or check, a new rule in a skill, an updated runbook. Close the entry in the breach register with the remedies.

## Severity table
| Severity | Examples | Actions |
|---|---|---|
| 1 Critical | other people's data read or altered; secret key published; accounts taken over; locations or art. 9 data exposed; SOS broken | at once: maintenance or read-only, revoke, rotate, sign everyone out; evidence; GDPR 72 hours; notice to people; whole team |
| 2 High | open flaw with no sign of use; one account taken over; bot or spam wave; scraping in progress | within hours: targeted fix, sign-ups closed or captcha, bans; logs checked to rule out access; register entry |
| 3 Medium | new Advisor warning; vulnerable dependency not reachable; failed attempts | within days: normal PR with the test that covers it |
| 4 Low | report with no effect, false alarm | note it and answer the reporter |

## Runbook template
```markdown
# Incident runbook — <project>  (offline copy at <where>; reviewed on <date>)
Lead: <name, phone> · Deputy: <name, phone> · Controller/DPO: <name, email>
Incident channel: <chat or phone> · Incident document: <link>
Consoles (2 admins, 2FA): Supabase <ref> · hosting <service> · DNS/registrar <…> · GitHub <org> · email <…> · payments <…>
Support: Supabase <link> · hosting <link> · supervisory authority: online notification procedure
Backups: plan <…> · PITR <yes/no> · own dump <where> · Storage files <where> · last restore tested <date>
Logs: retention <days> · export <how>
Maintenance: update public.app_status set maintenance = true, message = '<text>';
Read-only: update public.app_status set read_only = true;
Sign-ups: Authentication → Sign In / Providers → Allow new users to sign up = off
Everyone out: delete from auth.sessions; + JWT signing key rotation
Front-end rollback: <how, on the hosting> · Grants to reopen: <file>
Secrets to rotate (where): <list>
First hour: T0 → lead → severity → contain → evidence → GDPR decision → notices
Ready texts: <maintenance, user email, authority notification> · Breach register: <link>
```

## Limits to communicate
This skill does not replace a lawyer or a forensics firm: in serious incidents involve them early. The 72 hours run from awareness, not from the end of the investigation. The switch in the UI protects people, not data: the real shutdown is in the database. Rotating keys does not erase what has already been copied.
