---
name: api-sicura
description: Sicurezza delle API secondo la OWASP API Security Top 10 (2023), con REST, RPC e API generate come PostgREST/Supabase - accesso a oggetti altrui, campi privilegiati, limiti di consumo, funzioni riservate, flussi abusabili, inventario degli endpoint. Trigger - "API", "endpoint", "IDOR", "BOLA", "RPC", "rate limit", "OWASP API". EN - API security following the OWASP API Security Top 10 (2023) for REST, RPC and generated APIs like PostgREST/Supabase - object and property level authorization, resource limits, function level authorization, abusable business flows, endpoint inventory. Triggers - "API", "endpoint", "IDOR", "BOLA", "RPC", "rate limit", "OWASP API".
---

# API sicura · Secure APIs

> 🇮🇹 Versione italiana qui sotto · 🇬🇧 [English version below](#secure-apis-english)

Un'API è tutto ciò che si chiama senza passare dall'interfaccia: con un token e curl, un controllo fatto solo nel componente React non esiste. Con Supabase **ogni tabella, vista e funzione degli schemi esposti è un endpoint** (`/rest/v1/<tabella>`, `/rest/v1/rpc/<funzione>`), e nomi e chiave pubblica sono nel bundle JavaScript. Le regole seguono l'OWASP API Security Top 10 2023 (codice API1-API10 nei titoli) e valgono anche per REST, GraphQL, Edge Functions e server propri. Basi di Supabase: skill supabase-sicuro; limiti anti-molestie e scraping: sicurezza-social; posizioni: privacy-posizione; login: autenticazione-sicura; client: frontend-spa; WAF su server propri: difesa-attacchi; dati già usciti: risposta-incidenti.

## Regole obbligatorie

### 1. Inventario degli endpoint (API9 Improper Inventory Management)
- Tenere nella repo l'elenco di ciò che è raggiungibile: tabelle e viste esposte, RPC, Edge Functions, bucket, tabelle in Realtime, schemi esposti (impostazioni della Data API: solo `public`), API di terzi chiamate, webhook ricevuti. Per ognuno: chi lo chiama (anon, authenticated, ruolo), cosa restituisce, quali limiti. La parte del database si genera così:
```sql
select c.relname, c.relkind, c.relrowsecurity as rls,  -- tabelle e viste, permessi per colonna compresi
  has_any_column_privilege('anon', c.oid, 'select,insert,update') or has_table_privilege('anon', c.oid, 'delete') as anon,
  has_any_column_privilege('authenticated', c.oid, 'select,insert,update') or has_table_privilege('authenticated', c.oid, 'delete') as auth
from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relkind in ('r','p','v','m','f') order by 1;
select p.proname, pg_get_function_identity_arguments(p.oid) as args, p.prosecdef as definer, has_function_privilege('anon', p.oid, 'execute') as anon,
  has_function_privilege('authenticated', p.oid, 'execute') as auth from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' order by 1;  -- RPC
```
- La CI rigenera l'elenco sul database locale (`supabase start` con le migrazioni) e fallisce se cambia senza che il file sia aggiornato; ogni riga con `anon` o `definer` a `true` ha un motivo scritto. Versioni vecchie (`get_profile_v1`), funzioni di debug, tabelle di prova ed Edge Functions inutilizzate si cancellano con una migrazione: i nomi non sono un segreto. Anteprime e ambienti di prova usano un progetto separato con dati finti, mai la produzione con regole più larghe.

### 2. Negare per default
- Tabella nuova: RLS attiva, nessuna policy finché non serve, `grant` solo delle azioni necessarie (supabase-sicuro, punto 2). Una policy per azione (`for select`, `for insert`…): una `for all` vale anche per `delete`. Edge Functions e server propri: accesso richiesto su ogni rotta; le rotte pubbliche sono un elenco esplicito, ognuna con i suoi limiti.
- Funzioni: Postgres concede `execute` a `public` su ogni funzione nuova e Supabase anche ad `anon` e `authenticated`, quindi ogni funzione in `public` si chiama come RPC. Togliere il permesso per default e darlo una funzione alla volta con `grant execute on function … to authenticated`, anche alle funzioni usate nelle policy, che girano come chi chiama. Quelle esistenti si correggono con `revoke execute on function … from public, anon, authenticated`; l'inventario del punto 1 conferma il risultato. Helper delle policy, funzioni dei trigger e funzioni interne vanno nello schema `private`, non esposto.
```sql
alter default privileges for role postgres revoke execute on functions from public;
alter default privileges for role postgres in schema public revoke execute on functions from anon, authenticated;
```

### 3. Autorizzazione per oggetto (API1 Broken Object Level Authorization)
- Cosa è: l'API riceve un id e legge o modifica l'oggetto senza chiedersi se chi chiama ne ha diritto (`/messages?chat_id=eq.…` con la chat di un altro). È la falla più comune; gli uuid casuali non la chiudono, perché finiscono in link, URL e risposte.
- In PostgREST la difesa è la RLS: ogni policy lega la riga a `auth.uid()` (proprietario, partecipante, amico), mai a un id mandato dal client. Le viste saltano la RLS se non sono create `with (security_invoker = true)`; le viste materializzate non hanno RLS ma PostgREST le serve se stanno in uno schema esposto: metterle in `private` (o togliere `select` a `anon` e `authenticated`) e leggerle da una RPC che filtra per `auth.uid()`. Le RPC `security definer` e le Edge Functions con la chiave secret ricontrollano l'appartenenza nel codice; le Edge Functions che agiscono per l'utente creano il client con il suo token, così la RLS resta valida. Prova con il token di un utente di prova B sugli oggetti di A (password da variabile d'ambiente, mai nel codice):
```bash
J=(-H "apikey: $SB_KEY" -H "Content-Type: application/json")
TOKEN_B=$(curl -s "$SB_URL/auth/v1/token?grant_type=password" "${J[@]}" -d "{\"email\":\"$EMAIL_B\",\"password\":\"$PW_B\"}" | jq -r .access_token)
H=("${J[@]}" -H "Authorization: Bearer $TOKEN_B")
curl -s "$SB_URL/rest/v1/messages?chat_id=eq.$CHAT_A&select=*" "${H[@]}"                                          # atteso: []
curl -s -X PATCH "$SB_URL/rest/v1/meetups?id=eq.$MEETUP_A" "${H[@]}" -H "Prefer: return=representation" -d '{"title":"x"}'  # atteso: []
curl -s -X POST "$SB_URL/rest/v1/rpc/get_chat" "${H[@]}" -d "{\"chat_id\":\"$CHAT_A\"}"                         # atteso: errore
```
- Una modifica fermata dalla RLS non dà 403 ma zero righe: controllare il contenuto, non solo lo stato HTTP. Stesse prove su Storage (`/storage/v1/object/<bucket>/<percorso di A>`) e sui canali Realtime; la variante in SQL, con transazione annullata, è in supabase-sicuro, punto 7.

### 4. Autenticazione (API2 Broken Authentication)
- Cosa è: token accettati senza verifica, scadenze lunghe, login senza limiti, identità presa dal corpo della richiesta.
- L'identità viene solo dal token verificato: `auth.uid()` nel database; nelle Edge Functions `supabase.auth.getUser(token)` o la firma controllata con le chiavi pubbliche (JWKS) del progetto. Mai un JWT solo decodificato, mai un `user_id` letto dal body. Server propri: algoritmo fissato (mai `none`), `exp`, `iss` e `aud` controllati.
- Access token brevi: in Supabase la scadenza di default è un'ora, non alzarla. Gli accessi anonimi di Supabase hanno il ruolo `authenticated`: le policy riservate agli account veri aggiungono `(select (auth.jwt()->>'is_anonymous')::boolean) is false`. Login, iscrizione, recupero e OTP con limiti e captcha (autenticazione-sicura; supabase-sicuro, punto 6); mai token in URL, log o analytics.
- Prova: un token scaduto, con un carattere della firma cambiato o con `"alg":"none"` riceve 401 da REST, RPC ed Edge Functions; il `user_id` di un altro nel body viene ignorato o rifiutato.

### 5. Autorizzazione per proprietà (API3 Broken Object Property Level Authorization)
- Cosa è: la riga è giusta, le colonne no. In lettura escono campi riservati (email, data di nascita, posizione precisa, orientamento, `is_admin`); in scrittura il client imposta campi che non dovrebbe (`verified`, `role`, `plan`, `owner_id`, contatori: mass assignment).
- La RLS filtra le righe, non le colonne: con `select=*` PostgREST restituisce tutto ciò che il ruolo può leggere. Rimedio: permessi per colonna, o i dati privati in una tabella a parte leggibile solo dal proprietario.
```sql
revoke select, insert, update, delete on public.profiles from anon, authenticated;  -- il profilo lo crea un trigger all'iscrizione
grant select (id, display_name, bio, avatar_path, city) on public.profiles to authenticated;
grant update (display_name, bio, avatar_path, city) on public.profiles to authenticated;
```
- Con i permessi per colonna `select=*` dà errore: il client elenca le colonne. Le RPC dichiarano `returns table (…)` con i soli campi utili, mai `setof profiles`; i campi con visibilità scelta dall'utente passano da una funzione che applica la scelta (privacy-posizione). In Realtime pubblicare solo tabelle senza colonne riservate.
- Prova: con il proprio token, `PATCH /rest/v1/profiles?id=eq.<mio id>` con `{"verified":true}` fallisce con `permission denied` (42501); `select=birthdate` su un altro profilo fallisce; un abbonato Realtime di prova non riceve colonne riservate.

### 6. Autorizzazione per funzione (API5 Broken Function Level Authorization)
- Cosa è: azioni da moderatore o amministratore chiamabili da chiunque conosca il nome (`/rpc/ban_user`, `/admin/export`), o un ruolo scelto dal client.
- Ogni RPC riservata ha `execute` solo per chi serve (punto 2) e controlla il ruolo come prima istruzione: `if not exists (select 1 from private.staff where user_id = auth.uid() and role = 'moderator') then raise exception 'forbidden' using errcode = '42501'; end if;`. Il ruolo viene da una tabella nello schema `private` o da `app_metadata`, che solo il server scrive; mai da `user_metadata`, che l'utente cambia da solo con `auth.updateUser()`.
- Prova: come utente normale `POST /rest/v1/rpc/ban_user` fallisce; con la sola chiave pubblica (anon) falliscono tutte le RPC non pubbliche. Ripetere per ogni RPC dell'inventario con `definer = true` e per ogni metodo HTTP delle rotte di un server proprio.

### 7. Consumo di risorse (API4 Unrestricted Resource Consumption)
- Cosa è: richieste che costano troppo: pagine enormi, filtri lenti, file grandi, chiamate che fanno partire SMS, email, geocoding o AI pagati da voi.
- PostgREST: abbassare "Max rows" (impostazioni della Data API, default 1000) al massimo che l'app usa. Nelle RPC limitare sempre (`limit least(p_limit, 50)`), paginare a cursore (`where created_at < p_before`), accettare sulla mappa solo aree di dimensione massima.
- Timeout per ruolo (default Supabase: 3 s `anon`, 8 s `authenticated`), da abbassare se basta: `alter role anon set statement_timeout = '2s'; notify pgrst, 'reload config';`. Indici sulle colonne usate da policy e filtri: una policy lenta rallenta ogni richiesta. Conteggi esatti (`Prefer: count=exact`) solo su tabelle piccole. Storage con `file_size_limit` e `allowed_mime_types` su ogni bucket. Le Edge Functions che chiamano servizi a pagamento hanno una quota per utente al giorno in tabella e un tetto di spesa presso il fornitore.
- Prova: `GET /rest/v1/meetups?select=id&limit=100000` restituisce al massimo "Max rows"; l'RPC con `p_limit` 100000 ne restituisce 50.

### 8. Flussi sensibili e limiti per utente (API6 Unrestricted Access to Sensitive Business Flows)
- Cosa è: ogni passo è autorizzato, ma ripetuto da uno script diventa abuso: entrare in tutti i tavoli per vedere luoghi e partecipanti, occupare i posti di un evento, invitare migliaia di persone, recensioni false o a raffica, iscrizioni in massa, codici invito provati a forza.
- Elencare i flussi di valore e scrivere nel database le regole del flusso, non solo del record. Entrare in un tavolo: niente insert diretto su `meetup_members`, solo un'RPC che controlla capienza, invito o approvazione, blocchi ed età, con `unique (meetup_id, user_id)`. Recensioni: solo da chi ha partecipato, dopo la fine, una per coppia (`unique (meetup_id, reviewer_id, reviewed_id)`).
- Limiti per utente e per azione con `private.rate_limit` (sicurezza-social, punto 4), chiamato da trigger e RPC, più stretti per account nuovi; captcha davanti ai flussi più appetibili. Le RPC di lettura che registrano le chiamate (ricerca, mappa) devono essere `volatile`: nelle `stable` le scritture falliscono.
- Prova: uno script che chiama l'RPC 50 volte di fila riceve `rate_limited` oltre la soglia; un insert diretto in `meetup_members` è rifiutato.

### 9. Idempotenza e replay
- Doppi tocchi e reti instabili ripetono le richieste: due iscrizioni, due messaggi, due pagamenti. Ogni azione che crea qualcosa porta un id generato dal client (`crypto.randomUUID()`) con un vincolo unico; la ripetizione riceve 409 (violazione di unicità) e il client la tratta come riuscita.
- Link e codici monouso (inviti, "condividi il piano", recupero): nel database solo l'hash, con scadenza, consumati in modo atomico dentro l'RPC che li accetta. Webhook in arrivo: firma, finestra di tempo e id degli eventi già elaborati (punto 13). Un access token rubato resta valido fino alla scadenza anche dopo il logout: per questo è breve.
```sql
alter table public.messages add column client_id uuid, add constraint messages_once unique (sender_id, client_id);
update public.invites set used_at = now() where token_hash = encode(sha256(convert_to(p_token, 'UTF8')), 'hex')
  and used_at is null and expires_at > now() returning meetup_id;  -- nessuna riga: link non valido, scaduto o già usato
```
- Prova: lo stesso insert mandato due volte crea una sola riga; lo stesso link d'invito funziona una volta sola.

### 10. Validazione dell'input lato server
- Un client modificato manda qualsiasi cosa. Tipi, lunghezze, intervalli e valori ammessi si impongono nel database con vincoli e domini; nelle Edge Functions con uno schema (zod, valibot) che rifiuta i campi sconosciuti.
```sql
create domain public.lat as double precision check (value between -90 and 90);
alter table public.messages add constraint body_len check (char_length(body) between 1 and 2000);
alter table public.meetups add constraint seats_ok check (seats between 2 and 50), add constraint time_ok check (ends_at > starts_at),
  add constraint visibility_ok check (visibility in ('friends', 'public', 'invite')), add constraint meta_size check (pg_column_size(meta) < 4096);
```
- Le regole che dipendono dall'ora o da altre righe (evento nel futuro, al massimo un anno avanti, capienza) vanno in un trigger: un `check` deve dare sempre lo stesso risultato. Anche gli array hanno un massimo (`cardinality(tags) <= 10`). Testo libero salvato così com'è e reso sicuro all'output (React lo fa; niente `dangerouslySetInnerHTML`); URL accettati solo con `https:`. Mai SQL composto con testo del client (supabase-sicuro, punto 3).

### 11. Configurazione, errori e CORS (API8 Security Misconfiguration)
- Supabase: schemi esposti solo `public`; `pg_graphql` disattivata se GraphQL non si usa; nessuna chiave secret nel frontend; bucket privati; Security Advisor senza avvisi (supabase-sicuro). Risposte con dati personali: `Content-Type: application/json`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`; solo i metodi HTTP usati; nessun endpoint di debug o di stato che riveli versioni.
- Errori: PostgREST inoltra messaggio, dettaglio e suggerimento di Postgres, cioè nomi di tabelle e vincoli e a volte valori (`Key (email)=(…) already exists`). Nelle RPC e nei trigger rilanciare gli errori attesi con un codice stabile, senza dati e con lo stato HTTP giusto; l'interfaccia traduce i codici nella lingua dell'utente e non mostra mai `error.message` grezzo. Server propri: risposta generica con un id dell'errore, dettagli solo nei log (hardening-siti, punto 6).
```sql
raise sqlstate 'PGRST' using message = '{"code":"rate_limited","message":"Troppe richieste"}', detail = '{"status":429,"headers":{"Retry-After":"60"}}';
```
- CORS non è un controllo di accesso: decide solo quali siti leggono le risposte nel browser, non ferma curl né gli script. Le API che si autenticano con un token nell'header, come quelle di Supabase, possono accettare ogni origine; con cookie di sessione servono un elenco esplicito di origini, `Access-Control-Allow-Credentials: true` solo con un'origine esatta, mai l'`Origin` ricopiato senza controllo, mai `null`, sempre `Vary: Origin`. Nelle Edge Functions, su ogni risposta (`OPTIONS` compreso):
```ts
const ALLOWED = ['https://example.app'], origin = req.headers.get('Origin') ?? '';  // produzione e anteprime note
const cors = { Vary: 'Origin', 'Access-Control-Allow-Headers': 'authorization, apikey, content-type', 'Access-Control-Allow-Methods': 'POST, OPTIONS', ...(ALLOWED.includes(origin) ? { 'Access-Control-Allow-Origin': origin } : {}) };
```
- Prova: un errore voluto (duplicato, tipo sbagliato) non mostra nomi di tabelle, vincoli o valori; `curl -i -H 'Origin: https://evil.example'` verso la Edge Function non riceve `Access-Control-Allow-Origin`.

### 12. SSRF (API7 Server Side Request Forgery)
- Cosa è: il server scarica un URL scelto dall'utente (anteprima di un link, avatar da URL, import di un calendario, webhook configurabili) e così raggiunge reti interne o i metadati del cloud (`169.254.169.254`). Con Supabase succede nelle Edge Functions e con `pg_net`/`http` nel database: mai passare a queste un URL dell'utente senza controlli.
- Rimedio: meglio un elenco di host ammessi; altrimenti solo `https:` sulla porta 443, nome risolto e rifiutato se punta a indirizzi privati, di loopback, link-local o riservati (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `0.0.0.0/8`, `::1`, `::ffff:0:0/96`, `fc00::/7`, `fe80::/10`), redirect manuali (`redirect: 'manual'`) ricontrollati uno per uno, timeout breve, dimensione massima, tipo di contenuto atteso, mai la risposta grezza restituita all'utente. Un nome può cambiare indirizzo tra controllo e richiesta (DNS rebinding): nei casi delicati, un proxy in uscita con le stesse regole. Anteprime dei link in chat: generarle sul server con questi controlli, mai nel browser di chi riceve, che rivelerebbe il suo IP al sito del link.
- Prova: `http://169.254.169.254/latest/meta-data/`, `http://localhost:54321/`, `http://[::1]/`, un dominio che risolve in `127.0.0.1` e un URL che fa redirect verso uno di questi: tutti rifiutati.

### 13. API di terzi e webhook (API10 Unsafe Consumption of APIs)
- Cosa è: fidarsi di ciò che arriva da un'API esterna (mappe, geocoding, luoghi, login social, pagamenti, AI, metadati delle anteprime) come se fosse proprio.
- Validare le risposte con uno schema, limitarne tempo e dimensione, solo HTTPS, in caso di errore negare (fail closed). Nomi di luoghi, titoli e descrizioni sono testo non fidato: React li rende sicuri, `innerHTML` e i popup HTML delle mappe no (MapLibre: `setText`, non `setHTML`). URL ricevuti usati in `href` o `src` solo se `https:`. Chiavi segrete sul server o nelle Edge Functions; le chiavi che devono stare nel browser (mappe) limitate per dominio e quota presso il fornitore. Ai terzi il minimo: posizioni arrotondate, niente id interni (privacy-posizione).
- Webhook in arrivo (pagamenti, email, Database Webhooks di Supabase): firma HMAC verificata sul corpo grezzo con confronto a tempo costante, finestra di tempo di pochi minuti, id dell'evento salvato per scartare i doppioni, risposta 2xx rapida ed elaborazione idempotente; per i Database Webhooks un header segreto controllato dalla funzione. Codice: privacy-pagamenti.
- Prova: una risposta finta del fornitore con `<img src=x onerror=alert(1)>` nel nome di un luogo appare come testo e un URL `javascript:` non diventa un link; un webhook con firma sbagliata o vecchio di un'ora riceve 400 e non cambia nulla.

## Checklist
- [ ] Inventario generato e controllato in CI; `execute` revocato per default; nessuna tabella, vista o funzione esposta senza motivo; versioni vecchie cancellate.
- [ ] Prove curl con il token di un altro utente su tabelle, RPC, bucket e canali; viste `security_invoker`; permessi per colonna; RPC riservate con controllo del ruolo da `private` o `app_metadata`.
- [ ] Max rows, limiti nelle RPC, timeout, quote; limiti per utente sui flussi sensibili; id idempotenti; link monouso con hash; vincoli su ogni input; errori con codici stabili; CORS giusto; SSRF bloccato; risposte di terzi validate; webhook firmati.

## Limiti da comunicare
Le prove trovano i buchi che si cercano: vanno ripetute a ogni migrazione e prima di ogni rilascio. I limiti rallentano gli script, non li fermano: chi usa molti account resta possibile e va riconosciuto nei log e nelle segnalazioni. La RLS protegge i dati, non la logica dei flussi: le regole di business vanno scritte una per una. Una verifica esterna (penetration test) resta utile prima del lancio e dopo cambi grandi.

---

# Secure APIs (English)

An API is anything that can be called without going through the UI: with a token and curl, a check done only in the React component does not exist. With Supabase **every table, view and function in the exposed schemas is an endpoint** (`/rest/v1/<table>`, `/rest/v1/rpc/<function>`), and the names and the public key are in the JavaScript bundle. The rules follow the OWASP API Security Top 10 2023 (API1-API10 code in the headings) and also apply to REST, GraphQL, Edge Functions and your own servers. Supabase basics: supabase-sicuro skill; anti-harassment limits and scraping: sicurezza-social; locations: privacy-posizione; login: autenticazione-sicura; client: frontend-spa; WAF on your own servers: difesa-attacchi; data already leaked: risposta-incidenti.

## Mandatory rules

### 1. Endpoint inventory (API9 Improper Inventory Management)
- Keep in the repo the list of what is reachable: exposed tables and views, RPCs, Edge Functions, buckets, tables in Realtime, exposed schemas (Data API settings: `public` only), third-party APIs called, webhooks received. For each: who calls it (anon, authenticated, role), what it returns, which limits apply. The database part is generated like this:
```sql
select c.relname, c.relkind, c.relrowsecurity as rls,  -- tables and views, column grants included
  has_any_column_privilege('anon', c.oid, 'select,insert,update') or has_table_privilege('anon', c.oid, 'delete') as anon,
  has_any_column_privilege('authenticated', c.oid, 'select,insert,update') or has_table_privilege('authenticated', c.oid, 'delete') as auth
from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relkind in ('r','p','v','m','f') order by 1;
select p.proname, pg_get_function_identity_arguments(p.oid) as args, p.prosecdef as definer, has_function_privilege('anon', p.oid, 'execute') as anon,
  has_function_privilege('authenticated', p.oid, 'execute') as auth from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' order by 1;  -- RPCs
```
- CI regenerates the list on the local database (`supabase start` with the migrations) and fails if it changes without the file being updated; every row with `anon` or `definer` set to `true` has a written reason. Old versions (`get_profile_v1`), debug functions, test tables and unused Edge Functions are dropped with a migration: names are not a secret. Previews and test environments use a separate project with fake data, never production with looser rules.

### 2. Deny by default
- New table: RLS on, no policy until one is needed, `grant` only the actions required (supabase-sicuro, rule 2). One policy per action (`for select`, `for insert`…): a `for all` policy also covers `delete`. Edge Functions and your own servers: sign-in required on every route; public routes are an explicit list, each with its own limits.
- Functions: Postgres grants `execute` to `public` on every new function and Supabase also to `anon` and `authenticated`, so every function in `public` can be called as an RPC. Remove the privilege by default and grant it one function at a time with `grant execute on function … to authenticated`, including functions used in policies, which run as the caller. Fix existing ones with `revoke execute on function … from public, anon, authenticated`; the inventory from rule 1 confirms the result. Policy helpers, trigger functions and internal functions go in the `private` schema, which is not exposed.
```sql
alter default privileges for role postgres revoke execute on functions from public;
alter default privileges for role postgres in schema public revoke execute on functions from anon, authenticated;
```

### 3. Object-level authorization (API1 Broken Object Level Authorization)
- What it is: the API receives an id and reads or changes the object without asking whether the caller is entitled to it (`/messages?chat_id=eq.…` with someone else's chat). It is the most common flaw; random uuids do not close it, because they end up in links, URLs and responses.
- In PostgREST the defense is RLS: every policy ties the row to `auth.uid()` (owner, participant, friend), never to an id sent by the client. Views bypass RLS unless created `with (security_invoker = true)`; materialized views have no RLS but PostgREST serves them when they live in an exposed schema: keep them in `private` (or revoke `select` from `anon` and `authenticated`) and read them through an RPC that filters by `auth.uid()`. `security definer` RPCs and Edge Functions using the secret key re-check ownership in code; Edge Functions acting for the user create the client with the user's token, so RLS still applies. Test with test user B's token against A's objects (password from an environment variable, never in code):
```bash
J=(-H "apikey: $SB_KEY" -H "Content-Type: application/json")
TOKEN_B=$(curl -s "$SB_URL/auth/v1/token?grant_type=password" "${J[@]}" -d "{\"email\":\"$EMAIL_B\",\"password\":\"$PW_B\"}" | jq -r .access_token)
H=("${J[@]}" -H "Authorization: Bearer $TOKEN_B")
curl -s "$SB_URL/rest/v1/messages?chat_id=eq.$CHAT_A&select=*" "${H[@]}"                                          # expected: []
curl -s -X PATCH "$SB_URL/rest/v1/meetups?id=eq.$MEETUP_A" "${H[@]}" -H "Prefer: return=representation" -d '{"title":"x"}'  # expected: []
curl -s -X POST "$SB_URL/rest/v1/rpc/get_chat" "${H[@]}" -d "{\"chat_id\":\"$CHAT_A\"}"                         # expected: error
```
- An update stopped by RLS does not return 403 but zero rows: check the content, not just the HTTP status. Run the same tests on Storage (`/storage/v1/object/<bucket>/<A's path>`) and on Realtime channels; the SQL variant, in a rolled-back transaction, is in supabase-sicuro, rule 7.

### 4. Authentication (API2 Broken Authentication)
- What it is: tokens accepted without verification, long expiries, logins without limits, identity taken from the request body.
- Identity comes only from the verified token: `auth.uid()` in the database; in Edge Functions `supabase.auth.getUser(token)` or the signature checked against the project's public keys (JWKS). Never a merely decoded JWT, never a `user_id` read from the body. Your own servers: a fixed algorithm (never `none`), `exp`, `iss` and `aud` checked.
- Short access tokens: in Supabase the default expiry is one hour, do not raise it. Supabase anonymous sign-ins have the `authenticated` role: policies reserved for real accounts add `(select (auth.jwt()->>'is_anonymous')::boolean) is false`. Sign-in, sign-up, recovery and OTP with limits and a captcha (autenticazione-sicura; supabase-sicuro, rule 6); never tokens in URLs, logs or analytics.
- Test: an expired token, one with a changed signature character or one with `"alg":"none"` gets 401 from REST, RPC and Edge Functions; someone else's `user_id` in the body is ignored or rejected.

### 5. Property-level authorization (API3 Broken Object Property Level Authorization)
- What it is: the row is right, the columns are not. On read, restricted fields leak (email, birthdate, precise location, orientation, `is_admin`); on write, the client sets fields it should not (`verified`, `role`, `plan`, `owner_id`, counters: mass assignment).
- RLS filters rows, not columns: with `select=*` PostgREST returns everything the role can read. Fix: column grants, or private data in a separate table readable only by its owner.
```sql
revoke select, insert, update, delete on public.profiles from anon, authenticated;  -- a trigger creates the profile at sign-up
grant select (id, display_name, bio, avatar_path, city) on public.profiles to authenticated;
grant update (display_name, bio, avatar_path, city) on public.profiles to authenticated;
```
- With column grants `select=*` errors out: the client lists the columns. RPCs declare `returns table (…)` with only the useful fields, never `setof profiles`; fields whose visibility the user chooses go through a function that applies that choice (privacy-posizione). In Realtime publish only tables without restricted columns.
- Test: with your own token, `PATCH /rest/v1/profiles?id=eq.<my id>` with `{"verified":true}` fails with `permission denied` (42501); `select=birthdate` on another profile fails; a test Realtime subscriber receives no restricted columns.

### 6. Function-level authorization (API5 Broken Function Level Authorization)
- What it is: moderator or admin actions callable by anyone who knows the name (`/rpc/ban_user`, `/admin/export`), or a role chosen by the client.
- Every restricted RPC has `execute` only for those who need it (rule 2) and checks the role as its first statement: `if not exists (select 1 from private.staff where user_id = auth.uid() and role = 'moderator') then raise exception 'forbidden' using errcode = '42501'; end if;`. The role comes from a table in the `private` schema or from `app_metadata`, which only the server writes; never from `user_metadata`, which users change themselves with `auth.updateUser()`.
- Test: as a regular user `POST /rest/v1/rpc/ban_user` fails; with the public key alone (anon) every non-public RPC fails. Repeat for every RPC in the inventory with `definer = true` and for every HTTP method of your own server's routes.

### 7. Resource consumption (API4 Unrestricted Resource Consumption)
- What it is: requests that cost too much: huge pages, slow filters, large files, calls that trigger SMS, email, geocoding or AI you pay for.
- PostgREST: lower "Max rows" (Data API settings, default 1000) to the most the app uses. In RPCs always cap (`limit least(p_limit, 50)`), paginate with a cursor (`where created_at < p_before`), and accept only map areas of bounded size.
- Per-role timeouts (Supabase default: 3 s `anon`, 8 s `authenticated`), lowered if that is enough: `alter role anon set statement_timeout = '2s'; notify pgrst, 'reload config';`. Index the columns used by policies and filters: a slow policy slows every request. Exact counts (`Prefer: count=exact`) only on small tables. Storage with `file_size_limit` and `allowed_mime_types` on every bucket. Edge Functions that call paid services keep a per-user daily quota in a table and a spending cap with the provider.
- Test: `GET /rest/v1/meetups?select=id&limit=100000` returns at most "Max rows"; the RPC with `p_limit` 100000 returns 50.

### 8. Sensitive flows and per-user limits (API6 Unrestricted Access to Sensitive Business Flows)
- What it is: each step is authorized, but repeated by a script it becomes abuse: joining every table to see venues and attendees, filling all seats of an event, inviting thousands of people, fake or bulk reviews, mass sign-ups, brute-forcing invite codes.
- List the valuable flows and write the flow's rules in the database, not just the record's. Joining a table: no direct insert on `meetup_members`, only an RPC that checks capacity, invite or approval, blocks and age, with `unique (meetup_id, user_id)`. Reviews: only from attendees, after the end, one per pair (`unique (meetup_id, reviewer_id, reviewed_id)`).
- Per-user, per-action limits with `private.rate_limit` (sicurezza-social, rule 4), called from triggers and RPCs, stricter for new accounts; a captcha in front of the most attractive flows. Read RPCs that log calls (search, map) must be `volatile`: in `stable` functions writes fail.
- Test: a script calling the RPC 50 times in a row gets `rate_limited` past the threshold; a direct insert into `meetup_members` is rejected.

### 9. Idempotency and replay
- Double taps and flaky networks repeat requests: two sign-ups, two messages, two payments. Every action that creates something carries a client-generated id (`crypto.randomUUID()`) with a unique constraint; the repeat gets 409 (unique violation) and the client treats it as success.
- Single-use links and codes (invites, "share the plan", recovery): only the hash in the database, with an expiry, consumed atomically inside the RPC that accepts them. Incoming webhooks: signature, time window and ids of already processed events (rule 13). A stolen access token stays valid until it expires, even after logout: that is why it is short.
```sql
alter table public.messages add column client_id uuid, add constraint messages_once unique (sender_id, client_id);
update public.invites set used_at = now() where token_hash = encode(sha256(convert_to(p_token, 'UTF8')), 'hex')
  and used_at is null and expires_at > now() returning meetup_id;  -- no row: invalid, expired or already used link
```
- Test: the same insert sent twice creates a single row; the same invite link works only once.

### 10. Server-side input validation
- A modified client sends anything. Types, lengths, ranges and allowed values are enforced in the database with constraints and domains; in Edge Functions with a schema (zod, valibot) that rejects unknown fields.
```sql
create domain public.lat as double precision check (value between -90 and 90);
alter table public.messages add constraint body_len check (char_length(body) between 1 and 2000);
alter table public.meetups add constraint seats_ok check (seats between 2 and 50), add constraint time_ok check (ends_at > starts_at),
  add constraint visibility_ok check (visibility in ('friends', 'public', 'invite')), add constraint meta_size check (pg_column_size(meta) < 4096);
```
- Rules that depend on the clock or on other rows (event in the future, at most one year ahead, capacity) go in a trigger: a `check` must always give the same result. Arrays get a maximum too (`cardinality(tags) <= 10`). Free text stored as is and made safe on output (React does it; no `dangerouslySetInnerHTML`); URLs accepted only with `https:`. Never SQL built from client text (supabase-sicuro, rule 3).

### 11. Configuration, errors and CORS (API8 Security Misconfiguration)
- Supabase: exposed schemas `public` only; `pg_graphql` disabled if GraphQL is not used; no secret key in the frontend; private buckets; Security Advisor with no warnings (supabase-sicuro). Responses with personal data: `Content-Type: application/json`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`; only the HTTP methods in use; no debug or status endpoint that reveals versions.
- Errors: PostgREST passes on Postgres's message, detail and hint, that is table and constraint names and sometimes values (`Key (email)=(…) already exists`). In RPCs and triggers, re-raise expected errors with a stable code, no data and the right HTTP status; the UI translates codes into the user's language and never shows the raw `error.message`. Your own servers: a generic response with an error id, details only in the logs (hardening-siti, rule 6).
```sql
raise sqlstate 'PGRST' using message = '{"code":"rate_limited","message":"Too many requests"}', detail = '{"status":429,"headers":{"Retry-After":"60"}}';
```
- CORS is not access control: it only decides which sites can read responses in the browser, and does not stop curl or scripts. APIs that authenticate with a token in a header, like Supabase's, can accept any origin; with session cookies you need an explicit origin list, `Access-Control-Allow-Credentials: true` only with an exact origin, never the `Origin` echoed back unchecked, never `null`, always `Vary: Origin`. In Edge Functions, on every response (`OPTIONS` included):
```ts
const ALLOWED = ['https://example.app'], origin = req.headers.get('Origin') ?? '';  // production and known previews
const cors = { Vary: 'Origin', 'Access-Control-Allow-Headers': 'authorization, apikey, content-type', 'Access-Control-Allow-Methods': 'POST, OPTIONS', ...(ALLOWED.includes(origin) ? { 'Access-Control-Allow-Origin': origin } : {}) };
```
- Test: a deliberate error (duplicate, wrong type) shows no table names, constraints or values; `curl -i -H 'Origin: https://evil.example'` against the Edge Function gets no `Access-Control-Allow-Origin`.

### 12. SSRF (API7 Server Side Request Forgery)
- What it is: the server fetches a URL chosen by the user (link preview, avatar from URL, calendar import, configurable webhooks) and thereby reaches internal networks or cloud metadata (`169.254.169.254`). With Supabase this happens in Edge Functions and with `pg_net`/`http` in the database: never pass them a user URL without checks.
- Fix: preferably an allowlist of hosts; otherwise only `https:` on port 443, the name resolved and rejected if it points to private, loopback, link-local or reserved addresses (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `0.0.0.0/8`, `::1`, `::ffff:0:0/96`, `fc00::/7`, `fe80::/10`), manual redirects (`redirect: 'manual'`) re-checked one by one, a short timeout, a maximum size, the expected content type, and never the raw response returned to the user. A name can change address between check and request (DNS rebinding): for sensitive cases, an egress proxy with the same rules. Link previews in chat: generate them on the server with these checks, never in the recipient's browser, which would reveal the recipient's IP to the linked site.
- Test: `http://169.254.169.254/latest/meta-data/`, `http://localhost:54321/`, `http://[::1]/`, a domain resolving to `127.0.0.1` and a URL that redirects to one of these: all rejected.

### 13. Third-party APIs and webhooks (API10 Unsafe Consumption of APIs)
- What it is: trusting what comes from an external API (maps, geocoding, places, social login, payments, AI, preview metadata) as if it were your own.
- Validate responses with a schema, cap their time and size, HTTPS only, deny on error (fail closed). Place names, titles and descriptions are untrusted text: React makes them safe, `innerHTML` and HTML map popups do not (MapLibre: `setText`, not `setHTML`). URLs received are used in `href` or `src` only if `https:`. Secret keys on the server or in Edge Functions; keys that must live in the browser (maps) restricted by domain and quota with the provider. Send third parties the minimum: rounded locations, no internal ids (privacy-posizione).
- Incoming webhooks (payments, email, Supabase Database Webhooks): HMAC signature verified on the raw body with a constant-time comparison, a time window of a few minutes, the event id stored to drop duplicates, a quick 2xx response and idempotent processing; for Database Webhooks a secret header checked by the function. Code: privacy-pagamenti.
- Test: a fake provider response with `<img src=x onerror=alert(1)>` in a place name shows up as text and a `javascript:` URL does not become a link; a webhook with a wrong signature or an hour old gets 400 and changes nothing.

## Checklist
- [ ] Inventory generated and checked in CI; `execute` revoked by default; no table, view or function exposed without a reason; old versions dropped.
- [ ] curl tests with another user's token on tables, RPCs, buckets and channels; `security_invoker` views; column grants; restricted RPCs check the role from `private` or `app_metadata`.
- [ ] Max rows, caps in RPCs, timeouts, quotas; per-user limits on sensitive flows; idempotent ids; hashed single-use links; constraints on every input; errors with stable codes; correct CORS; SSRF blocked; third-party responses validated; signed webhooks.

## Limitations to communicate
Tests find the holes you look for: repeat them at every migration and before every release. Limits slow scripts down, they do not stop them: an attacker with many accounts is still possible and must be spotted in logs and reports. RLS protects data, not the logic of flows: business rules must be written one by one. An external assessment (penetration test) is still worthwhile before launch and after big changes.
