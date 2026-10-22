---
name: supabase-sicuro
description: Mette in sicurezza un progetto Supabase (Postgres, RLS, Auth, Storage, Realtime). Regole di accesso su ogni tabella, permessi espliciti, funzioni SECURITY DEFINER, bucket, impostazioni di Auth, chiavi API e prove come utenti diversi. Trigger - "Supabase", "RLS", "policy", "migrazione", "anon key", "service role", "bucket", "row level security". EN - Secures a Supabase project (Postgres, RLS, Auth, Storage, Realtime) - access rules on every table, explicit grants, SECURITY DEFINER functions, buckets, Auth settings, API keys and tests as different users. Triggers - "Supabase", "RLS", "policy", "migration", "anon key", "service role", "storage bucket", "row level security".
---

# Supabase sicuro · Secure Supabase

> 🇮🇹 Versione italiana qui sotto · 🇬🇧 [English version below](#secure-supabase-english)

Con Supabase il browser parla direttamente con il database (PostgREST, RPC, Storage, Realtime) usando la chiave pubblica. **Ogni tabella e ogni funzione è un'API pubblica**: l'unica difesa sono le regole nel database. Chi conosce l'indirizzo del progetto e la chiave pubblica (sono nel codice del sito) può chiamare tutto ciò che le regole permettono.

## Regole obbligatorie

### 1. RLS su ogni tabella, sempre
- `alter table … enable row level security` nella stessa migrazione che crea la tabella. Una tabella senza policy con RLS attiva non si legge: è il punto di partenza giusto.
- Le policy dicono chi vede quali righe (`using`) e cosa può scrivere (`with check`). Nelle insert e update, il proprietario si lega sempre a `auth.uid()` (`with check (user_id = (select auth.uid()))`), mai a un valore scelto dal client.
- Le colonne privilegiate (verificato, piano, ruolo, contatori, stato di una richiesta) non si aggiornano dal client. Si usano permessi per colonna (`grant update (bio, city) on … to authenticated`) o trigger che le rifiutano.
- I dati altrui sensibili (data di nascita, posizione, email, telefono) si escludono con permessi per colonna, o si espongono solo tramite funzioni che restituiscono il minimo (l'età, una posizione arrotondata).

### 2. Permessi espliciti sulle tabelle nuove (dal 30 ottobre 2026)
Una tabella nuova nello schema `public` non è più esposta da sola all'API. Ogni migrazione che la crea deve dire chi può usarla:
```sql
grant select, insert, delete on public.commenti to authenticated;  -- solo le azioni che servono
-- anon solo se la tabella si legge senza accesso
```
Senza `grant` l'app riceve "permission denied", con il suggerimento del comando. Le tabelle esistenti non cambiano.

### 3. Funzioni
- `security invoker` (il default) quando bastano le regole di chi chiama.
- Le `security definer` (girano con i privilegi del proprietario) devono:
  - avere `set search_path = ''` e nomi completi (`public.tabella`);
  - controllare chi chiama con `auth.uid()` e i suoi diritti sui dati toccati;
  - togliere l'esecuzione a tutti e ridarla solo a chi serve: `revoke execute on function … from public, anon, authenticated;` poi `grant execute on function … to authenticated;`. Le funzioni interne vanno in uno schema non esposto:
```sql
create schema if not exists private;
revoke all on schema private from public, anon;
alter default privileges in schema private revoke execute on functions from public;
grant usage on schema private to authenticated;  -- solo se le policy usano funzioni di private
```
- Mai SQL dinamico con testo del client. Se serve, usare `format('%I', …)` e `%L`.

### 4. Storage
- Bucket privati per default. Pubblici solo per immagini davvero pubbliche.
- Le policy di `storage.objects` legano il percorso al proprietario: `(storage.foldername(name))[1] = (select auth.uid())::text` per insert, update e delete.
- Limitare tipi e dimensioni sul bucket (`allowed_mime_types`, `file_size_limit`). Niente HTML o SVG caricati dagli utenti in un bucket pubblico: sarebbero pagine eseguibili sul dominio di Supabase.
- Togliere i dati EXIF e GPS dalle foto nel browser (ridisegnarle su un canvas) come primo livello; un client modificato lo salta, quindi caricare in un bucket privato di quarantena e ricodificare lato server prima di pubblicare (privacy-posizione §6, sicurezza-social).
- Nei bucket pubblici l'URL è permanente e il percorso si vede: `<uid>/foto.jpg` rivela l'id della persona. Nomi casuali, oppure bucket privati con URL firmati a scadenza breve.

### 5. Chiavi API
- Nel browser va **solo** la chiave pubblica: oggi la *publishable* (`sb_publishable_…`). Le vecchie `anon` e `service_role` (JWT) spariscono entro la fine del 2026: migrare e poi disattivarle in Settings → API Keys.
- La chiave *secret* / `service_role` scavalca la RLS: solo su server o in Edge Functions, mai nel frontend né nella repo. Se finisce in un commit, va ruotata subito.

### 6. Auth
Nella dashboard controllare:
- conferma dell'email attiva;
- password lunghe: almeno 12 caratteri (8 è il minimo assoluto), controllate contro le password trapelate; le regole di composizione (lettere, numeri, simboli) sono facoltative, contano di più lunghezza e controllo (NIST SP 800-63B);
- protezione dalle password trapelate (piano Pro);
- scadenza breve dei codici OTP;
- cambio email sicuro, con conferma su entrambi gli indirizzi;
- Redirect URLs solo verso i propri domini, niente `*` aperti;
- limiti di frequenza su accessi, iscrizioni ed email;
- captcha (hCaptcha o Turnstile) sull'iscrizione, subito se l'app fa incontrare sconosciuti;
- cambio password sicuro (richiede un nuovo accesso recente);
- MFA (TOTP) disponibile, e obbligatoria per moderatori, staff e amministratori: le policy delle loro azioni chiedono `(select auth.jwt() ->> 'aal') = 'aal2'`;
- collegamento automatico delle identità (Google e email con lo stesso indirizzo): accettarlo solo con email verificate dal provider.

Nell'app:
- i messaggi non devono rivelare se un'email è registrata, quando questo conta (enumerazione);
- se l'app salva più sessioni (cambio account), le chiavi di accesso nel browser valgono quanto la password: niente XSS, CSP stretta.

### 7. Prove come utenti diversi
Ogni regola si prova in due direzioni (consentito e negato), dentro una transazione che si annulla:
```sql
do $$ begin
  perform set_config('request.jwt.claims', json_build_object('sub', '<uuid B>', 'role', 'authenticated')::text, true);
  perform set_config('role', 'authenticated', true);
  -- B non deve vedere i dati privati di A:
  if exists (select 1 from public.messaggi where autore = '<uuid A>' and privato) then raise exception 'FAIL'; end if;
  raise exception 'DRY RUN OK';  -- annulla sempre
end $$;
```
Dopo ogni migrazione: Security Advisor e Performance Advisor senza avvisi nuovi. Le prove più importanti diventano test automatici: pgTAP con `supabase test db` su un database locale, eseguito nella CI a ogni PR.

### 8. Privacy
- Posizioni mai esatte se non servono: arrotondarle nel database (trigger), non solo nell'app.
- Minimo indispensabile nelle risposte delle RPC.
- La cancellazione dell'account deve togliere davvero dati e file (diritto all'oblio).

### 9. Realtime
- `postgres_changes` filtra con la RLS gli inserimenti e le modifiche, ma **gli eventi DELETE arrivano a tutti gli iscritti della tabella**, con la chiave primaria (con `replica identity full` anche il resto della riga vecchia). Nella pubblicazione `supabase_realtime` mettere solo tabelle i cui id non dicono nulla: mai presenze, blocchi, amicizie, posizioni.
- Per dati personali in tempo reale usare **canali privati** (Broadcast o Presence con `config: { private: true }`) e nelle impostazioni di Realtime togliere l'accesso pubblico, così esistono solo canali privati.
- Chi può ascoltare o scrivere su un canale lo decidono le policy su `realtime.messages`:
```sql
create policy "membri ascoltano" on realtime.messages for select to authenticated
  using (realtime.messages.extension in ('broadcast', 'presence')
         and private.puo_entrare(realtime.topic()));   -- es. 'tavolo:<id>' → è membro?
create policy "membri scrivono" on realtime.messages for insert to authenticated
  with check (private.puo_entrare(realtime.topic()));
```

### 10. Piattaforma
- Settings → Database: SSL obbligatorio, Network Restrictions sulle connessioni dirette (solo gli IP che servono), password del database lunga e cambiata quando qualcuno esce dal team.
- Leva d'emergenza: in Settings → API si può spegnere la Data API (PostgREST); in Auth si chiudono le iscrizioni (risposta-incidenti).
- Viste e viste materializzate: `security_invoker = on` sulle viste; le materializzate non hanno RLS, quindi in uno schema non esposto (api-sicura).
- Backup e PITR verificati con un ripristino di prova; chi può scaricarli è un elenco breve.

---

# Secure Supabase (English)

With Supabase the browser talks to the database directly (PostgREST, RPC, Storage, Realtime) with the public key. **Every table and every function is a public API**: the database rules are the only defense. Anyone who knows the project URL and the public key (both are in the site's code) can call whatever the rules allow.

## Mandatory rules

### 1. RLS on every table, always
- `alter table … enable row level security` in the same migration that creates the table. A table with RLS on and no policy cannot be read: that is the right starting point.
- Policies say who sees which rows (`using`) and what they may write (`with check`). For inserts and updates, always tie the owner to `auth.uid()` (`with check (user_id = (select auth.uid()))`), never to a client-chosen value.
- Privileged columns (verified, plan, role, counters, a request's status) are not client-updatable. Use column grants (`grant update (bio, city) on … to authenticated`) or triggers that reject them.
- Other people's sensitive data (birthdate, location, email, phone) is excluded with column grants, or exposed only through functions that return the minimum (the age, a rounded location).

### 2. Explicit grants on new tables (from 30 October 2026)
A new table in the `public` schema is no longer exposed to the API on its own. Every migration that creates one must say who can use it:
```sql
grant select, insert, delete on public.comments to authenticated;  -- only the actions you need
-- anon only if the table is readable without signing in
```
Without a `grant` the app gets "permission denied", with a hint showing the command. Existing tables are unaffected.

### 3. Functions
- `security invoker` (the default) when the caller's own rules are enough.
- `security definer` ones (they run with the owner's privileges) must:
  - set `search_path = ''` and use fully qualified names (`public.table`);
  - check the caller with `auth.uid()` and the caller's rights on the data they touch;
  - drop execute from everyone and give it back only where needed: `revoke execute on function … from public, anon, authenticated;` then `grant execute on function … to authenticated;`. Internal functions belong in an unexposed schema:
```sql
create schema if not exists private;
revoke all on schema private from public, anon;
alter default privileges in schema private revoke execute on functions from public;
grant usage on schema private to authenticated;  -- only if policies call functions in private
```
- Never dynamic SQL with client text. If needed, use `format('%I', …)` and `%L`.

### 4. Storage
- Private buckets by default. Public only for truly public images.
- `storage.objects` policies tie the path to the owner: `(storage.foldername(name))[1] = (select auth.uid())::text` for insert, update and delete.
- Restrict types and sizes on the bucket (`allowed_mime_types`, `file_size_limit`). No user-uploaded HTML or SVG in a public bucket: they would be executable pages on Supabase's domain.
- Strip EXIF and GPS from photos in the browser (redraw them on a canvas) as a first layer; a modified client skips it, so upload to a private quarantine bucket and re-encode server-side before publishing (privacy-posizione §6, sicurezza-social).
- In public buckets the URL is permanent and the path shows: `<uid>/photo.jpg` reveals the person's id. Random names, or private buckets with short-lived signed URLs.

### 5. API keys
- Only the public key goes in the browser: today the *publishable* one (`sb_publishable_…`). The old `anon` and `service_role` (JWT) keys go away by the end of 2026: migrate, then disable them in Settings → API Keys.
- The *secret* / `service_role` key bypasses RLS: server or Edge Functions only, never in the frontend or the repo. If it lands in a commit, rotate it at once.

### 6. Auth
In the dashboard, check:
- email confirmation on;
- long passwords: at least 12 characters (8 is the absolute minimum), checked against leaked passwords; composition rules (letters, digits, symbols) are optional, length and the leaked check matter more (NIST SP 800-63B);
- leaked password protection (Pro plan);
- short OTP expiry;
- secure email change, confirmed on both addresses;
- Redirect URLs only to your own domains, no open `*`;
- rate limits on sign-ins, sign-ups and emails;
- a captcha (hCaptcha or Turnstile) on sign-up, from day one if the app makes strangers meet;
- secure password change (requires a recent sign-in);
- MFA (TOTP) available, and mandatory for moderators, staff and admins: the policies of their actions require `(select auth.jwt() ->> 'aal') = 'aal2'`;
- automatic identity linking (Google and email with the same address): accept it only with emails verified by the provider.

In the app:
- messages must not reveal whether an email is registered, where that matters (enumeration);
- if the app stores several sessions (account switching), the access tokens in the browser are worth as much as the password: no XSS, a strict CSP.

### 7. Tests as different users
Test every rule both ways (allowed and denied), inside a transaction that always rolls back:
```sql
do $$ begin
  perform set_config('request.jwt.claims', json_build_object('sub', '<uuid B>', 'role', 'authenticated')::text, true);
  perform set_config('role', 'authenticated', true);
  -- B must not see A's private data:
  if exists (select 1 from public.messages where author = '<uuid A>' and private) then raise exception 'FAIL'; end if;
  raise exception 'DRY RUN OK';  -- always rolls back
end $$;
```
After every migration: no new warnings from the Security Advisor and the Performance Advisor. The key tests become automated: pgTAP with `supabase test db` on a local database, run in CI on every PR.

### 8. Privacy
- Never store exact locations unless needed: round them in the database (a trigger), not only in the app.
- Return the bare minimum from RPCs.
- Account deletion must really remove data and files (right to erasure).

### 9. Realtime
- `postgres_changes` filters inserts and updates through RLS, but **DELETE events reach every subscriber of the table**, with the primary key (with `replica identity full`, the rest of the old row too). Only put tables whose ids say nothing into the `supabase_realtime` publication: never presence, blocks, friendships, locations.
- For personal data in real time use **private channels** (Broadcast or Presence with `config: { private: true }`) and turn off public access in the Realtime settings, so only private channels exist.
- Who may listen or write on a channel is decided by policies on `realtime.messages`:
```sql
create policy "members listen" on realtime.messages for select to authenticated
  using (realtime.messages.extension in ('broadcast', 'presence')
         and private.can_join(realtime.topic()));   -- e.g. 'table:<id>' → is a member?
create policy "members write" on realtime.messages for insert to authenticated
  with check (private.can_join(realtime.topic()));
```

### 10. Platform
- Settings → Database: SSL enforced, Network Restrictions on direct connections (only the IPs that need them), a long database password changed whenever someone leaves the team.
- Emergency lever: in Settings → API you can turn off the Data API (PostgREST); in Auth you can close sign-ups (risposta-incidenti).
- Views and materialized views: `security_invoker = on` on views; materialized views have no RLS, so keep them in an unexposed schema (api-sicura).
- Backups and PITR verified with a test restore; a short list of who can download them.
