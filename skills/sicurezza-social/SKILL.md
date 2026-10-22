---
name: sicurezza-social
description: Sicurezza per app social e di incontri dal vivo - blocchi applicati nel database, segnalazioni e moderazione, limiti anti-molestie e anti-spam, anti-stalking, profili falsi e truffe, contenuti degli utenti e obblighi DSA. Trigger - "blocca utente", "segnalazioni", "moderazione", "molestie", "spam", "bot", "profili falsi", "trust and safety". EN - Trust and safety for social and meet-in-person apps - database-enforced blocking, reports and moderation, anti-harassment and anti-spam limits, anti-stalking, fake profiles and scams, user content and DSA duties. Triggers - "block user", "reports", "moderation", "harassment", "spam", "bots", "fake profiles", "trust and safety".
---

# Sicurezza social · Social trust and safety

> 🇮🇹 Versione italiana qui sotto · 🇬🇧 [English version below](#social-trust-and-safety-english)

In un'app dove le persone si scrivono, si vedono sulla mappa e si incontrano dal vivo, un errore di sicurezza fa male fuori dallo schermo: molestie, stalking, truffe, incontri finiti male. Queste regole valgono per ogni app con profili, messaggi, mappe, storie o eventi tra sconosciuti. **Ciò che protegge una persona va applicato nel database o sul server**: un pulsante nascosto nell'interfaccia non ferma chi chiama l'API direttamente (skill supabase-sicuro). Posizioni in dettaglio: skill privacy-posizione; API: api-sicura; violazioni di dati: risposta-incidenti.

## Regole obbligatorie

### 1. Blocco bidirezionale, applicato nel database
- Bloccare rende due persone invisibili l'una all'altra, nei due versi: profilo, mappa e posizione, chat, tavoli ed eventi, elenchi di partecipanti, storie, ricerca, suggerimenti, notifiche. Chi è bloccato non riceve avvisi.
- La regola sta nelle policy, non nei filtri del client:
```sql
create table public.blocks (
  blocker uuid not null default auth.uid() references auth.users on delete cascade,
  blocked uuid not null references auth.users on delete cascade,
  primary key (blocker, blocked), check (blocker <> blocked));
alter table public.blocks enable row level security;
create policy "solo i propri blocchi" on public.blocks for all to authenticated
  using (blocker = (select auth.uid())) with check (blocker = (select auth.uid()));
grant select, insert, delete on public.blocks to authenticated;
-- solo l'altra persona come argomento: con due id si scoprirebbero i blocchi tra terzi
create function private.blocked_with(other uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.blocks where (blocker = auth.uid() and blocked = other)
                                               or (blocker = other and blocked = auth.uid())); $$;
revoke execute on function private.blocked_with(uuid) from public, anon;
grant usage on schema private to authenticated;  -- la policy gira come chi chiama
grant execute on function private.blocked_with(uuid) to authenticated;
-- in ogni policy che mostra righe di altri: using (<condizione attuale> and not private.blocked_with(owner_id))
```
- Un trigger sull'inserimento in `blocks` cancella nei due versi amicizia, richieste in sospeso, inviti e condivisione della posizione; i messaggi nuovi si rifiutano con `with check (not private.blocked_with(<destinatario>))`. Chi è bloccato non vede i tavoli e gli eventi di chi l'ha bloccato e non può entrarci; negli eventi di terzi i due non si vedono tra i partecipanti.
- Realtime: Postgres Changes rispetta la RLS di select; Broadcast e Presence no, a meno di canali privati con policy su `realtime.messages`. Niente canale Presence condiviso per la mappa o per "chi è online".
- Notifiche push ed email: la funzione che le invia ricontrolla il blocco al momento dell'invio. Media personali (storie, foto in chat) in bucket privati con URL firmati brevi: un bucket pubblico serve il file a chiunque abbia il link.
- Prova: dopo che A blocca B, come B ogni tabella, RPC e canale che mostra persone non restituisce A, e viceversa (skill supabase-sicuro, punto 7).

### 2. Segnalazioni con categorie e prove
- "Segnala" su profilo, messaggio, storia, foto, tavolo o evento, gruppo, in due tocchi, con "Blocca" offerto subito. Categorie fisse: pericolo immediato, persona minorenne, abuso sessuale su minori, immagini intime senza consenso, minacce o violenza, molestie, odio, profilo falso o furto d'identità, truffa o spam, altro contenuto illegale, autolesionismo, altro. "Pericolo immediato" mostra prima il 112.
- Prove copiate dal server, non inviate dal client: una RPC `report_content(kind, target_id, category, note)` salva in `reports` un'istantanea (testo, id del file, autore, ora) e qualche messaggio di contesto. Le prove restano anche se l'autore cancella, e nessuno può allegare "prove" inventate.
- RLS: chi segnala legge solo le proprie segnalazioni e il loro stato; la persona segnalata non vede mai segnalazioni né segnalanti; i moderatori passano da RPC che controllano il ruolo.
- Conservare le prove per il tempo della decisione, dei reclami e delle richieste delle autorità, poi cancellarle, e scriverlo nell'informativa privacy. Contro le segnalazioni usate come arma: contare segnalanti distinti, pesare l'età dell'account, limitare le segnalazioni per persona al giorno.

### 3. Coda di moderazione, tempi ed escalation
- Una coda unica con priorità: pericolo immediato e minori, poi minacce, immagini intime, molestie, profili falsi e truffe, il resto.
- Obiettivi di tempo scritti (esempio da adattare): pericolo e minori entro 1 ora, minacce e molestie entro 24 ore, il resto entro 72 ore. Quando nessuno è di turno, misure automatiche: oltre una soglia di segnalanti distinti il contenuto si nasconde in attesa di revisione e l'account perde il contatto con sconosciuti.
- Strumento di moderazione: pagina con accesso, ruolo verificato nel database, azioni solo via RPC (avviso, rimozione, limite temporaneo, sospensione, ban), registro di ogni azione con chi, quando e perché; mai la chiave `service_role` nel browser. Il moderatore vede prova e contesto, non l'intera cronologia privata; anteprime delle immagini sfocate di default.
- Escalation: 1) moderatore; 2) responsabile per ban definitivi, casi dubbi e richieste delle autorità; 3) autorità. Il DSA (art. 18) obbliga i servizi di hosting a informare subito le autorità quando vengono a sapere di un possibile reato che minaccia la vita o la sicurezza di persone. Contatti e procedura scritti in anticipo.

### 4. Anti-molestie: richieste di messaggio e limiti lato server
- Il primo messaggio da chi non è amico va in "Richieste": solo testo, lunghezza limitata, niente link, foto o numeri di telefono, un solo messaggio finché il destinatario non accetta. Lo impone un trigger sulla tabella dei messaggi, non il componente. Nessuno entra in un gruppo o in un tavolo senza accettare un invito.
- Limiti per ora e per giorno su nuove conversazioni, richieste di amicizia, follow, inviti e segnalazioni, con una tabella contatore nello schema `private` (senza grant ai ruoli dell'API):
```sql
create table private.action_log (user_id uuid not null, action text not null,
  at timestamptz not null default now());
create index on private.action_log (user_id, action, at);
create function private.rate_limit(p_action text, p_max int, p_window interval)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is null then return; end if;  -- job di servizio; anon è già fermato dalla RLS
  perform pg_advisory_xact_lock(hashtext(auth.uid()::text || p_action));  -- niente corse
  if (select count(*) from private.action_log where user_id = auth.uid()
      and action = p_action and at > now() - p_window) >= p_max then
    -- risposta HTTP 429 con codice stabile, come chiede api-sicura
    raise sqlstate 'PGRST' using message = '{"code":"rate_limited","message":"Troppe richieste"}',
      detail = '{"status":429,"headers":{"Retry-After":"60"}}';
  end if;
  insert into private.action_log (user_id, action) values (auth.uid(), p_action);
end $$;
-- nel trigger before insert (security definer) di friend_requests, invites, conversations, follows:
--   perform private.rate_limit('friend_request', 20, interval '1 hour');
```
- Valori di partenza da adattare: 10 nuove conversazioni con sconosciuti all'ora, 20 richieste di amicizia all'ora, 30 inviti all'ora; la metà per account con meno di 7 giorni. Pulire il registro con un job (pg_cron); l'interfaccia traduce `rate_limited` in un messaggio chiaro. Lo stesso testo inviato a molte persone (stesso hash) è un segnale di spam: rallentare l'account e metterlo in coda di revisione.

### 5. Anti-stalking
- Mai la posizione esatta di un'altra persona: arrotondata su una griglia fissa (per esempio ~250 m; il rumore casuale si annulla facendo la media), aggiornata con ritardo o solo dopo spostamenti significativi (skill privacy-posizione).
- Distanze a fasce ("meno di 1 km"), mai "a 320 m": distanze precise chieste da punti diversi permettono di triangolare. Rifiutare posizioni del client che saltano in modo impossibile e limitare la frequenza di cambi di posizione e di ricerche sulla mappa.
- "Ultimo accesso" vago ("attivo oggi") o nascosto, a scelta; conferme di lettura disattivabili. Nascondersi da persone specifiche senza bloccarle (posizione, storie, stato) e modalità invisibile, con effetto immediato nel database (riga cancellata o policy), non un flag che il client può ignorare.
- Storie con pubblico scelto (amici, lista ristretta, persone escluse) e scadenza applicata sul server cancellando righe e file.
- Controllo da parte di un partner o di un ex: promemoria periodico di chi vede la posizione, avviso quando qualcuno nuovo ottiene l'accesso, un tasto per nascondere tutto subito, l'elenco delle sessioni e dei dispositivi attivi con "esci da tutti".
- SOS: contatti fidati scelti prima; l'SOS manda la posizione precisa solo a loro, per un tempo limitato, poi scade da solo; non avvisa la persona che si sta incontrando; ricorda il 112 e non promette di sostituirlo. Provarlo dall'inizio alla fine prima di ogni rilascio.

### 6. Incontri dal vivo
- Tavoli ed eventi in luoghi pubblici: il luogo si sceglie tra posti pubblici della mappa, non da un indirizzo privato; l'indirizzo preciso di un evento privato lo vedono solo i partecipanti accettati, vicino all'ora dell'evento.
- Chi crea il tavolo approva chi entra; l'elenco dei partecipanti lo vedono solo i partecipanti. "Condividi il piano": un link per un amico con luogo, ora e partecipanti, che scade dopo l'evento.
- Prima del primo incontro, consigli brevi (luogo pubblico, mezzi propri, dire a qualcuno dove si va); dopo, "com'è andata?" con scorciatoia per segnalare.

### 7. Profili falsi e bot
- Conferma dell'email obbligatoria e captcha (Turnstile o hCaptcha) all'iscrizione. In Supabase la captcha di Auth vale per iscrizioni, accessi e recupero password; per chiederla solo oltre una soglia serve un passaggio lato server (Edge Function) che decide.
- Velocità per IP e dispositivo: molte iscrizioni dalla stessa rete, molte richieste nella prima ora, lo stesso testo a molti → limiti più stretti o revisione. Telefono facoltativo, come segnale in più; limitare paesi e frequenza degli SMS contro le frodi sugli invii (SMS pumping).
- Badge "verificato" solo dopo un controllo reale (selfie dal vivo confrontato con le foto, da un moderatore o da un fornitore). La colonna non è scrivibile dal client (permessi per colonna o trigger, skill supabase-sicuro) e il badge decade se cambiano le foto. Mai autodichiarato, mai acquistabile. Il confronto del volto è un dato biometrico (art. 9 GDPR): consenso esplicito e cancellazione del selfie dopo il controllo.
- Ban: conservare un'impronta di email e telefono per fermare le reiscrizioni, con un hash con chiave (HMAC) e la chiave in Supabase Vault, non nella tabella: un hash semplice si inverte provando tutte le email o i numeri. Resta un dato personale: base giuridica il legittimo interesse (art. 6(1)(f)) e tempi di conservazione scritti. 18+: data di nascita all'iscrizione, rifiuto sotto i 18 anni, categoria "persona minorenne" che sospende l'account in attesa di verifica.

### 8. Impersonificazione e truffe
- Nomi riservati: nome dell'app, "admin", "supporto", "staff" e varianti con caratteri simili. I messaggi ufficiali arrivano da un canale di sistema con un segno grafico legato a un campo del database, non al nome visualizzato. L'app dice chiaramente che nessuno del team chiede password, codici o denaro in chat.
- Schemi da riconoscere: amore dichiarato subito, invito a spostarsi su un'altra app, richieste di denaro, carte regalo, cripto o "investimenti", rifiuto di videochiamate e incontri, richiesta di foto intime seguita da ricatto (sextortion).
- Link e numeri bloccati nel primo contatto (punto 4); dopo, link mostrati con il dominio in vista; avviso al destinatario quando un messaggio parla di soldi, bonifici o cripto.
- Foto rubate a una persona reale: categoria dedicata e ricerca inversa delle immagini nello strumento di moderazione.
- Locali e organizzatori finti usati come esca: verificare l'attività (partita IVA, indirizzo) prima del segno di verifica, controllare che il luogo di un evento sia pubblico, limitare gli inviti di massa dagli account business.
- Recensioni anonime: mostrarle solo come totali dopo un numero minimo e con un ritardo, altrimenti chi le ha scritte si riconosce dall'ora o dalle poche persone presenti.
- Notifiche push: la chiave privata VAPID è un segreto, gli endpoint push sono dati personali, il testo sullo schermo bloccato è minimo; prima di inviare si ricontrollano blocchi e visibilità.

### 9. Contenuti degli utenti e obblighi di legge
- Immagini: sul bucket `allowed_mime_types` solo JPEG, PNG, WebP e `file_size_limit`; niente SVG o HTML. Caricamento in un bucket privato di quarantena; una Edge Function controlla i byte reali, ricodifica (via EXIF e GPS) e solo allora pubblica. Il canvas nel browser aiuta, ma un client modificato lo salta.
- Nudità e violenza: classificatore automatico più revisione umana; regole più severe per le foto profilo; immagini da sconosciuti sfocate finché chi le riceve non sceglie di vederle.
- Contenuti illegali: il DSA (Reg. UE 2022/2065) chiede a ogni servizio di hosting un meccanismo di segnalazione (art. 16) e una motivazione a chi subisce una rimozione o una limitazione (art. 17). Un ordine di rimozione di contenuti terroristici da un'autorità UE va eseguito entro un'ora (Reg. UE 2021/784).
- Abuso sessuale su minori (CSAM): togliere subito l'accesso, non inoltrare né scaricare il file, conservare le prove in modo protetto e segnalare alle autorità (in Italia la Polizia Postale, commissariatodips.it; chi opera negli Stati Uniti deve segnalare al CyberTipline del NCMEC). Valutare il confronto con hash noti (PhotoDNA, CSAM Scanning Tool di Cloudflare).
- Immagini intime senza consenso: rimozione prioritaria; indicare StopNCII.org e, in Italia, la segnalazione al Garante privacy (art. 144-bis del Codice privacy).

### 10. Enumerazione e scraping
- Nessun endpoint che elenca tutti gli utenti: `profiles` si legge solo dentro una relazione (amici, stesso tavolo); la ricerca passa da una RPC con almeno 3 caratteri, massimo 20 risultati, campi minimi, blocchi esclusi e limite di frequenza.
- Mappa: la RPC dei tavoli vicini accetta un'area di dimensione massima, restituisce pochi risultati e nessun id dei partecipanti. In Supabase abbassare "Max rows" nelle impostazioni dell'API (default 1000); paginazione a cursore con un numero massimo di pagine.
- Niente oracoli di esistenza dove conta: stessi messaggi in iscrizione e recupero password; il controllo "nome utente libero" solo da autenticati e con limite. "Trova amici dai contatti" solo con consenso reciproco: l'hash dei numeri di telefono non protegge, i numeri possibili sono pochi e si provano tutti.
- Riferimenti: OWASP API Security Top 10 2023, API1 (Broken Object Level Authorization) e API6 (Unrestricted Access to Sensitive Business Flows). Pagine pubbliche di profilo, se esistono: dati minimi e `noindex`.

### 11. Dati sensibili del profilo
- Orientamento sessuale, opinioni politiche e convinzioni religiose sono categorie particolari (art. 9 GDPR): facoltativi, con consenso esplicito, visibilità per campo (solo io, amici, tutti) e privati di default. L'identità di genere merita la stessa cura.
- Nessun filtro o ricerca per questi campi aperto a sconosciuti: creerebbe liste di bersagli. In modalità viaggio proporre di nasconderli: in alcuni paesi esporli è pericoloso. Mai nelle risposte verso persone bloccate o sconosciute: permessi per colonna o una funzione che restituisce solo i campi consentiti.

### 12. Regole della community, termini e trasparenza
- Linee guida in linguaggio semplice: cosa è vietato, cosa succede (avviso, limite, sospensione, ban), come si fa reclamo. Mostrate all'iscrizione e collegate dal flusso di segnalazione. Il DSA (art. 14) chiede termini chiari anche su moderazione, strumenti automatici e revisione umana.
- Chi segnala riceve subito una conferma e poi l'esito (ricevuta, in esame, azione presa, nessuna violazione) con le possibilità di ricorso (art. 16). Mai rivelare chi ha segnalato alla persona segnalata.
- Chi subisce una misura riceve la motivazione (art. 17) e un canale di reclamo. Le piattaforme che non sono micro o piccole imprese (art. 19) devono avere anche un sistema interno di reclami (art. 20) e misure contro gli abusi ripetuti (art. 23). Punti di contatto per autorità e utenti indicati nel sito (art. 11 e 12).

## Checklist
- [ ] Blocco provato come utenti diversi: nessuna tabella, RPC, canale Realtime, notifica o bucket mostra l'altra persona.
- [ ] "Segnala" ovunque con prove copiate dal server; coda con priorità, tempi scritti, registro delle azioni ed escalation.
- [ ] Richieste di messaggio e limiti di frequenza nel database; posizioni arrotondate, distanze a fasce, "nascondi a", SOS provato.
- [ ] Badge non scrivibile dal client, captcha e conferma email; upload in quarantena e ricodificati; procedure CSAM e DSA scritte.
- [ ] Nessun elenco di utenti né oracolo di esistenza; campi sensibili privati e non filtrabili; linee guida e punti di contatto pubblicati.

## Limiti da comunicare
Nessuna misura tecnica rende sicuro un incontro dal vivo: riduce il rischio e accelera la risposta. Senza persone che guardano la coda, segnalazioni e SOS restano promesse. I classificatori automatici sbagliano in entrambi i sensi. Gli obblighi di legge citati (DSA, GDPR, CSAM) vanno verificati con un legale per il proprio paese e la dimensione dell'azienda.

---

# Social trust and safety (English)

In an app where people message each other, see each other on a map and meet in person, a security mistake hurts off-screen: harassment, stalking, scams, meetings gone wrong. These rules apply to every app with profiles, messages, maps, stories or events between strangers. **Whatever protects a person must be enforced in the database or on the server**: a button hidden in the UI does not stop someone who calls the API directly (supabase-sicuro skill). Locations in detail: privacy-posizione skill; APIs: api-sicura; data breaches: risposta-incidenti.

## Mandatory rules

### 1. Bidirectional blocking, enforced in the database
- Blocking makes two people invisible to each other, both ways: profile, map and location, chats, tables and events, attendee lists, stories, search, suggestions, notifications. The blocked person gets no alert.
- The rule lives in the policies, not in client filters:
```sql
create table public.blocks (
  blocker uuid not null default auth.uid() references auth.users on delete cascade,
  blocked uuid not null references auth.users on delete cascade,
  primary key (blocker, blocked), check (blocker <> blocked));
alter table public.blocks enable row level security;
create policy "own blocks only" on public.blocks for all to authenticated
  using (blocker = (select auth.uid())) with check (blocker = (select auth.uid()));
grant select, insert, delete on public.blocks to authenticated;
-- only the other person as argument: with two ids anyone could probe blocks between third parties
create function private.blocked_with(other uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.blocks where (blocker = auth.uid() and blocked = other)
                                               or (blocker = other and blocked = auth.uid())); $$;
revoke execute on function private.blocked_with(uuid) from public, anon;
grant usage on schema private to authenticated;  -- the policy runs as the caller
grant execute on function private.blocked_with(uuid) to authenticated;
-- in every policy that shows other people's rows: using (<current condition> and not private.blocked_with(owner_id))
```
- A trigger on insert into `blocks` deletes, both ways, friendship, pending requests, invites and location sharing; new messages are rejected with `with check (not private.blocked_with(<recipient>))`. The blocked person does not see the blocker's tables and events and cannot join them; at third-party events the two do not see each other among attendees.
- Realtime: Postgres Changes respects the select RLS; Broadcast and Presence do not, unless you use private channels with policies on `realtime.messages`. No shared Presence channel for the map or for "who's online".
- Push and email notifications: the function that sends them re-checks the block at send time. Personal media (stories, chat photos) in private buckets with short signed URLs: a public bucket serves the file to anyone holding the link.
- Test: after A blocks B, as B no table, RPC or channel that shows people returns A, and vice versa (supabase-sicuro skill, rule 7).

### 2. Reports with categories and evidence
- "Report" on profile, message, story, photo, table or event, group, within two taps, with "Block" offered right away. Fixed categories: immediate danger, underage person, child sexual abuse, non-consensual intimate images, threats or violence, harassment, hate, fake profile or identity theft, scam or spam, other illegal content, self-harm, other. "Immediate danger" shows the emergency number (112 in the EU) first.
- Evidence copied by the server, not sent by the client: an RPC `report_content(kind, target_id, category, note)` stores in `reports` a snapshot (text, file id, author, time) and a few context messages. Evidence survives if the author deletes, and nobody can attach made-up "evidence".
- RLS: reporters read only their own reports and their status; the reported person never sees reports or reporters; moderators go through RPCs that check the role.
- Keep evidence for the time of the decision, appeals and requests from authorities, then delete it, and say so in the privacy notice. Against weaponised reporting: count distinct reporters, weigh account age, cap reports per person per day.

### 3. Moderation queue, targets and escalation
- One queue with priorities: immediate danger and minors, then threats, intimate images, harassment, fake profiles and scams, the rest.
- Written time targets (example to adapt): danger and minors within 1 hour, threats and harassment within 24 hours, the rest within 72 hours. When nobody is on duty, automatic measures: above a threshold of distinct reporters the content is hidden pending review and the account loses contact with strangers.
- Moderation tool: a signed-in page, role verified in the database, actions only via RPC (warning, removal, temporary limit, suspension, ban), a log of every action with who, when and why; never the `service_role` key in the browser. Moderators see the evidence and its context, not the whole private history; image previews blurred by default.
- Escalation: 1) moderator; 2) a lead for permanent bans, unclear cases and requests from authorities; 3) authorities. The DSA (Art. 18) requires hosting services to promptly inform the authorities when they become aware of a possible criminal offence threatening someone's life or safety. Contacts and procedure written down in advance.

### 4. Anti-harassment: message requests and server-side limits
- The first message from a non-friend goes to "Requests": text only, limited length, no links, photos or phone numbers, a single message until the recipient accepts. A trigger on the messages table enforces it, not the component. Nobody joins a group or a table without accepting an invite.
- Hourly and daily limits on new conversations, friend requests, follows, invites and reports, with a counter table in the `private` schema (no grants to the API roles):
```sql
create table private.action_log (user_id uuid not null, action text not null,
  at timestamptz not null default now());
create index on private.action_log (user_id, action, at);
create function private.rate_limit(p_action text, p_max int, p_window interval)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is null then return; end if;  -- service jobs; anon is already stopped by RLS
  perform pg_advisory_xact_lock(hashtext(auth.uid()::text || p_action));  -- no races
  if (select count(*) from private.action_log where user_id = auth.uid()
      and action = p_action and at > now() - p_window) >= p_max then
    -- HTTP 429 with a stable code, as api-sicura asks
    raise sqlstate 'PGRST' using message = '{"code":"rate_limited","message":"Too many requests"}',
      detail = '{"status":429,"headers":{"Retry-After":"60"}}';
  end if;
  insert into private.action_log (user_id, action) values (auth.uid(), p_action);
end $$;
-- in the before insert trigger (security definer) of friend_requests, invites, conversations, follows:
--   perform private.rate_limit('friend_request', 20, interval '1 hour');
```
- Starting values to adapt: 10 new conversations with strangers per hour, 20 friend requests per hour, 30 invites per hour; half for accounts younger than 7 days. Prune the log with a job (pg_cron); the UI turns `rate_limited` into a clear message. The same text sent to many people (same hash) is a spam signal: slow the account down and queue it for review.

### 5. Anti-stalking
- Never another person's exact location: rounded to a fixed grid (e.g. ~250 m; random noise cancels out by averaging), updated with a delay or only after significant moves (privacy-posizione skill).
- Distances in bands ("under 1 km"), never "320 m away": precise distances queried from different points allow trilateration. Reject client positions that jump impossibly and rate-limit position changes and map searches.
- "Last seen" vague ("active today") or hidden, by choice; read receipts can be turned off. Hiding from specific people without blocking them (location, stories, status) and an invisible mode, effective immediately in the database (row deleted or policy), not a flag the client can ignore.
- Stories with a chosen audience (friends, close list, excluded people) and expiry enforced on the server by deleting rows and files.
- Control by a partner or an ex: a periodic reminder of who sees the location, an alert when someone new gains access, one button to hide everything at once, the list of active sessions and devices with "sign out everywhere".
- SOS: trusted contacts chosen beforehand; SOS sends the precise location only to them, for a limited time, then expires on its own; it does not alert the person being met; it points to the emergency number (112 in the EU) and never claims to replace it. Test it end to end before every release.

### 6. Meeting in person
- Tables and events in public places: the venue is picked among public places on the map, not from a private address; a private event's exact address is visible only to accepted attendees, close to the event time.
- The table's creator approves who joins; only attendees see the attendee list. "Share the plan": a link for a friend with place, time and attendees, expiring after the event.
- Before a first meeting, short tips (public place, own transport, tell someone where you're going); afterwards, "how did it go?" with a shortcut to report.

### 7. Fake profiles and bots
- Mandatory email confirmation and a captcha (Turnstile or hCaptcha) at sign-up. In Supabase the Auth captcha applies to sign-ups, sign-ins and password recovery; to require it only above a threshold you need a server-side step (Edge Function) that decides.
- Velocity per IP and device: many sign-ups from the same network, many requests in the first hour, the same text to many people → tighter limits or review. Phone optional, as an extra signal; restrict countries and SMS frequency against SMS pumping fraud.
- "Verified" badge only after a real check (live selfie matched against the photos, by a moderator or a vendor). The column is not client-writable (column grants or a trigger, supabase-sicuro skill) and the badge lapses when the photos change. Never self-asserted, never for sale. Face matching is biometric data (GDPR Art. 9): explicit consent, and delete the selfie after the check.
- Bans: keep a fingerprint of email and phone to stop re-registration, using a keyed hash (HMAC) with the key in Supabase Vault, not in the table: a plain hash is reversed by trying every email or number. It is still personal data: legitimate interest as the lawful basis (art. 6(1)(f)) and a written retention period. 18+: birthdate at sign-up, refusal under 18, an "underage person" category that suspends the account pending verification.

### 8. Impersonation and scams
- Reserved names: the app's name, "admin", "support", "staff" and look-alike variants. Official messages come from a system channel with a mark tied to a database field, not to the display name. The app states clearly that nobody from the team asks for passwords, codes or money in chat.
- Patterns to recognise: instant declarations of love, invitations to move to another app, requests for money, gift cards, crypto or "investments", refusal of video calls and meetings, requests for intimate photos followed by blackmail (sextortion).
- Links and numbers blocked in the first contact (rule 4); later, links shown with the domain visible; a warning to the recipient when a message talks about money, transfers or crypto.
- Photos stolen from a real person: a dedicated category and reverse image search in the moderation tool.
- Fake venues and organisers used as bait: verify the business (VAT number, address) before the verified badge, check that an event's venue is public, limit mass invites from business accounts.
- Anonymous reviews: show them only as totals after a minimum number and with a delay, otherwise the author is recognised from the time or the few people present.
- Push notifications: the VAPID private key is a secret, push endpoints are personal data, the lock-screen text is minimal; blocks and visibility are re-checked before sending.

### 9. User-generated content and legal duties
- Images: on the bucket, `allowed_mime_types` JPEG, PNG, WebP only and a `file_size_limit`; no SVG or HTML. Upload into a private quarantine bucket; an Edge Function checks the real bytes, re-encodes (dropping EXIF and GPS) and only then publishes. Canvas in the browser helps, but a modified client skips it.
- Nudity and violence: an automatic classifier plus human review; stricter rules for profile photos; images from strangers blurred until the recipient chooses to see them.
- Illegal content: the DSA (Regulation (EU) 2022/2065) requires every hosting service to offer a notice mechanism (Art. 16) and to give a statement of reasons to anyone whose content is removed or restricted (Art. 17). A removal order for terrorist content from an EU authority must be executed within one hour (Regulation (EU) 2021/784).
- Child sexual abuse material (CSAM): remove access at once, do not forward or download the file, preserve evidence securely and report to the authorities (in Italy the Polizia Postale, commissariatodips.it; providers operating in the United States must report to NCMEC's CyberTipline). Consider matching against known hashes (PhotoDNA, Cloudflare's CSAM Scanning Tool).
- Non-consensual intimate images: priority removal; point to StopNCII.org and, in Italy, to reporting to the Garante privacy (Art. 144-bis of the Italian Privacy Code).

### 10. Enumeration and scraping
- No endpoint that lists all users: `profiles` is readable only within a relationship (friends, same table); search goes through an RPC with at least 3 characters, at most 20 results, minimal fields, blocks excluded and a rate limit.
- Map: the nearby-tables RPC accepts an area of bounded size, returns few results and no attendee ids. In Supabase lower "Max rows" in the API settings (default 1000); cursor pagination with a maximum number of pages.
- No existence oracles where it matters: identical messages on sign-up and password recovery; the "username available" check only for signed-in users and rate-limited. "Find friends from contacts" only with mutual consent: hashing phone numbers does not protect them, the possible numbers are few and can all be tried.
- References: OWASP API Security Top 10 2023, API1 (Broken Object Level Authorization) and API6 (Unrestricted Access to Sensitive Business Flows). Public profile pages, if any: minimal data and `noindex`.

### 11. Sensitive profile data
- Sexual orientation, political opinions and religious beliefs are special categories (GDPR Art. 9): optional, with explicit consent, per-field visibility (only me, friends, everyone) and private by default. Gender identity deserves the same care.
- No filter or search on these fields open to strangers: it would build target lists. In travel mode, offer to hide them: in some countries exposing them is dangerous. Never in responses to blocked people or strangers: column grants or a function that returns only the allowed fields.

### 12. Community guidelines, terms and transparency
- Guidelines in plain language: what is forbidden, what happens (warning, limit, suspension, ban), how to appeal. Shown at sign-up and linked from the report flow. The DSA (Art. 14) requires clear terms, including on moderation, automated tools and human review.
- Reporters get an immediate acknowledgement and then the outcome (received, under review, action taken, no violation) with the options for redress (Art. 16). Never reveal the reporter to the reported person.
- Anyone hit by a measure gets a statement of reasons (Art. 17) and an appeal channel. Platforms that are not micro or small enterprises (Art. 19) also need an internal complaint-handling system (Art. 20) and measures against repeated misuse (Art. 23). Points of contact for authorities and users published on the site (Art. 11 and 12).

## Checklist
- [ ] Blocking tested as different users: no table, RPC, Realtime channel, notification or bucket shows the other person.
- [ ] "Report" everywhere with server-copied evidence; prioritised queue, written targets, action log and escalation.
- [ ] Message requests and rate limits in the database; rounded locations, distance bands, "hide from", SOS tested.
- [ ] Badge not client-writable, captcha and email confirmation; uploads quarantined and re-encoded; CSAM and DSA procedures written down.
- [ ] No user listing or existence oracles; sensitive fields private and not filterable; guidelines and points of contact published.

## Limitations to communicate
No technical measure makes an in-person meeting safe: it lowers the risk and speeds up the response. Without people watching the queue, reports and SOS remain promises. Automatic classifiers err both ways. The legal duties cited (DSA, GDPR, CSAM) must be checked with a lawyer for your country and company size.
