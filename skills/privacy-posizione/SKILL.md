---
name: privacy-posizione
description: Protegge la posizione e i dati personali sensibili - posizioni arrotondate nel database, niente distanze esatte, GPS tolto dalle foto, consensi GDPR art. 9, conservazione, esportazione e cancellazione. Trigger - "posizione", "geolocalizzazione", "amici vicini", "privacy", "GDPR", "dati sensibili", "cancellazione account", "EXIF". EN - Protects location and sensitive personal data - server-side rounding, no exact distances, GPS stripped from photos, GDPR art. 9 consent, retention, export and erasure. Triggers - "location", "geolocation", "nearby friends", "privacy", "GDPR", "sensitive data", "delete account", "EXIF".
---

# Privacy di posizione e dati sensibili · Location and Sensitive Data Privacy

> 🇮🇹 Versione italiana qui sotto · 🇬🇧 [English version below](#location-and-sensitive-data-privacy-english)

In un'app dove le persone si incontrano dal vivo, la posizione e i dati delicati (orientamento, religione, idee politiche, salute) sono quelli che fanno più danni se escono: stalking, outing, aggressioni, furti in casa vuota. Valgono le regole di supabase-sicuro (RLS, grant, funzioni) e di hardening-siti; questa skill dice **quanto** dato tenere e **chi** può ricavarlo. Principio: la precisione che un utente ottiene combinando tutte le API (mappa, liste, filtri, distanze, notifiche) non deve superare quella che si vuole mostrargli.

## Regole obbligatorie

### 1. Raccogliere il minimo
- Per ogni dato scrivere a cosa serve; se nessuna funzione lo usa, non si raccoglie. Per "chi è in zona" basta una cella di qualche centinaio di metri, per gli sconosciuti basta la città.
- Niente storico delle posizioni: una riga per utente, sovrascritta, che scade. Lo storico rivela casa, lavoro e abitudini.
- Chiedere la posizione al browser solo quando l'utente attiva la funzione, con `enableHighAccuracy: false`. Se l'app la usa, `Permissions-Policy: geolocation=(self)` al posto di `geolocation=()` (hardening-siti).

### 2. Arrotondare nel database, a griglia
- L'arrotondamento nel client non protegge: chiunque può chiamare l'API con coordinate esatte. Arrotondare in un trigger prima di salvare, così il dato grezzo non esiste.
- Usare una griglia fissa e salvare il **centro della cella**. Uno spostamento casuale nuovo a ogni lettura si annulla facendo la media di molte letture; uno spostamento fisso per utente si scopre una volta (incontrando la persona o conoscendo un suo indirizzo) e poi vale per sempre. La griglia dà sempre la stessa cella: ripetere le letture non aggiunge nulla.
- Il passaggio da una cella all'altra rivela il confine: cambiare cella solo quando la persona è entrata nella nuova di almeno un quarto di cella (isteresi).
- Fuori città 250 m possono indicare una sola casa: celle più grandi dove le persone sono poche, o solo il nome della località.
```sql
create function private.snap_cell() returns trigger
language plpgsql set search_path = '' as $$
declare
  dlat constant float8 := 0.00225;  -- ~250 m nord-sud
  dlng float8;
begin
  -- isteresi: vicino alla cella di prima (meno di un quarto dentro la nuova) si resta lì
  if tg_op = 'UPDATE' and old.lat is not null
     and abs(new.lat - old.lat) < 0.75 * dlat
     and abs(new.lng - old.lng) < 0.75 * dlat / greatest(cos(radians(old.lat)), 0.2) then
    new.lat := old.lat; new.lng := old.lng;
    return new;
  end if;
  new.lat := (floor(new.lat / dlat) + 0.5) * dlat;           -- centro della cella
  dlng := dlat / greatest(cos(radians(new.lat)), 0.2);       -- ~250 m anche est-ovest
  new.lng := (floor(new.lng / dlng) + 0.5) * dlng;
  return new;
end $$;
create trigger snap_cell before insert or update of lat, lng on public.presenze
  for each row execute function private.snap_cell();
```

### 3. Niente oracoli di distanza
- La trilaterazione, documentata su diverse app di incontri: l'attaccante falsifica la propria posizione, legge la distanza da tre punti e ritrova la vittima a pochi metri. Funziona anche con distanze arrotondate e filtri "entro X km", cercando il punto in cui il valore cambia.
- Mai distanze esatte. Fasce larghe (`< 1 km`, `1–5 km`, `5–20 km`, `> 20 km`) calcolate tra centri di cella, mai tra punti grezzi. Agli sconosciuti, al massimo la distanza tra città.
- Raggi dei filtri scelti tra pochi valori fissi, non un numero libero. Niente ordinamento per distanza fine: ordinare per fascia, poi per un criterio che non dipende dalla distanza (attività, nome).
- La posizione di chi cerca arriva dal client e può essere falsa: arrotondarla come le altre, rifiutare salti impossibili (centinaia di km in pochi minuti), limitare la frequenza di cambi di posizione e ricerche (difesa-attacchi).

### 4. Chi vede cosa, e per quanto
- Condivisione spenta per default; si accende con un gesto esplicito e mostra un indicatore finché è attiva. La presenza ha una scadenza (`expires_at`): la policy la filtra, un job la cancella.
- Solo gli amici vedono la cella; ognuno può nascondersi a singoli amici; i blocchi valgono nei due sensi e ovunque (mappa, liste, storie, gruppi). Gli sconosciuti vedono al massimo la città.
- Modalità viaggio: agli sconosciuti la città di destinazione solo durante il viaggio, non prima. Annunciarlo in anticipo dice anche che la casa è vuota.
- Tavoli ed eventi in luoghi pubblici possono avere l'indirizzo esatto; quelli in casa mostrano solo la zona finché l'organizzatore non accetta. L'elenco dei partecipanti lo vede solo chi partecipa.
- Supabase Realtime: `postgres_changes` applica la RLS a inserimenti e modifiche, ma gli eventi DELETE arrivano a tutti gli iscritti con la chiave primaria: tabelle di presenze, blocchi o amicizie non vanno nella pubblicazione `supabase_realtime`. Broadcast e presence passano dalla RLS solo nei canali privati con policy su `realtime.messages`. Niente posizioni su canali pubblici (dettagli in supabase-sicuro).
- "Aggiornato" arrotondato ("adesso", "oggi"), non al secondo. Le notifiche ("X è vicino") usano la fascia: passano dai server di Apple e Google e restano sullo schermo bloccato.
```sql
create policy "presenza visibile agli amici" on public.presenze for select to authenticated
using (expires_at > now() and (
  user_id = (select auth.uid())
  or private.puo_vedere_presenza(user_id)  -- security definer: amicizia, non nascosto, non bloccato
));
select cron.schedule('presenze-scadute', '*/15 * * * *',
  $$delete from public.presenze where expires_at < now()$$);
```

### 5. Mappe e geocoding di terzi
- Ogni richiesta di tile o di geocoding porta al fornitore l'IP dell'utente, il `Referer` e, per i tile, zona e zoom: chi guarda sempre la stessa via a zoom alto rivela dove abita. Il geocoding inverso invia le coordinate.
- Geocoding inverso sul centro della cella, mai sul punto grezzo; nelle ricerche al massimo 3 decimali (circa 110 m).
- Il Nominatim pubblico di OpenStreetMap ha regole d'uso: al massimo 1 richiesta al secondo, niente ricerca mentre si scrive, applicazione identificata, attribuzione. Ogni richiesta porta l'IP dell'utente alla OSM Foundation: cercare solo all'invio, passare da un proprio proxy o ospitare un'istanza propria.
- Tile serviti da sé (per esempio un file PMTiles su storage o CDN propri) o tramite un proxy (Edge Function) che toglie IP e cookie; altrimenti un fornitore che non profila, dichiarato nell'informativa.
- `Referrer-Policy: strict-origin-when-cross-origin` (o `no-referrer`) e solo i domini necessari nella CSP. Mai coordinate negli URL dell'app (`?lat=…&lng=…`): finiscono in cronologia, log, analytics e `Referer`.

### 6. Foto e video senza GPS
- Le foto del telefono hanno spesso le coordinate esatte nell'EXIF. Ridisegnarle su un canvas prima del caricamento crea un file nuovo senza metadati:
```js
async function senzaMetadati(file) {
  const img = await createImageBitmap(file);
  const canvas = new OffscreenCanvas(img.width, img.height);
  canvas.getContext('2d').drawImage(img, 0, 0);
  return canvas.convertToBlob({ type: 'image/jpeg', quality: 0.85 }); // niente EXIF né GPS
}
```
- Il client si può aggirare: dove possibile ripetere la pulizia lato server (Edge Function, trasformazione immagini) e controllare a campione i file salvati con `exiftool -gps:all <file>`.
- I video conservano la posizione nel contenitore: accettarli solo con un passaggio lato server (`ffmpeg -i in.mp4 -map_metadata -1 -c copy out.mp4`).

### 7. SOS: l'unica eccezione
- La posizione esatta solo nell'SOS, solo verso i contatti scelti dall'utente, con consenso esplicito dato quando si configura la funzione, non nel momento del pericolo.
- Mentre è attivo: indicatore sempre visibile, pulsante per fermarlo, arresto automatico dopo un tempo stabilito.
- Tabella separata con RLS (leggono l'utente e i destinatari), conservazione breve e scritta (per esempio 72 ore) con cancellazione automatica. Mai nella presenza normale, nei log o nelle analytics.

### 8. Dati dell'art. 9 GDPR
- Categorie particolari (art. 9(1)): origine etnica, opinioni politiche, convinzioni religiose o filosofiche, appartenenza sindacale, dati genetici, dati biometrici usati per identificare (per esempio il confronto del volto per verificare un profilo), salute, vita sessuale e orientamento sessuale. L'identità di genere non è nominata, ma può rivelare orientamento o salute: trattarla allo stesso modo.
- Serve il **consenso esplicito** (art. 9(2)(a)): una casella per dato, non spuntata, separata dai termini di servizio, che dice chi lo vedrà. Salvare data e versione del testo. Revocare dev'essere facile quanto acconsentire (art. 7(3)); la revoca cancella il dato.
- Campi sempre facoltativi, con "preferisco non dirlo". Visibilità per campo (solo io / amici / tutti), di default la più stretta.
- Contano anche i dati dedotti: far parte di un gruppo LGBTQ+, di una parrocchia o di un partito può rivelarli. Membri visibili solo ai membri; gruppi delicati privati per default.
- Niente ricerche o filtri sugli sconosciuti per questi campi (servirebbero a costruire liste); niente pubblicità o profilazione senza un consenso a parte.
- Attenzione alle deduzioni da conteggi e filtri: un tavolo "solo LGBTQ+" con il numero di persone compatibili in zona, ristretto finché resta una persona, rivela il suo orientamento. Conteggi a fasce con un minimo ("meno di 10"), nessun conteggio quando luogo e attributo restringono troppo, limiti di frequenza; scriverlo nella DPIA.

### 9. Età: 18+
- Controllare la maggiore età all'iscrizione nel database (trigger), non solo nel modulo. Prevedere la segnalazione dei profili che sembrano di minori, con revisione e sospensione.
- Agli altri solo l'età, mai la data di nascita: la data in uno schema che l'API non espone, l'età da una funzione interna usata dalle RPC che restituiscono un profilo già visibile a chi chiede (rispettando blocchi e privacy). Chiamabile da tutti, darebbe l'età di chiunque, anche di chi ti ha bloccato.
```sql
create function private.eta(uid uuid) returns int
language sql stable security definer set search_path = '' as $$
  select extract(year from age(n.data_nascita))::int from private.nascite n where n.user_id = uid
$$;
revoke execute on function private.eta(uuid) from public, anon, authenticated;
```

### 10. GDPR: basi, documenti, fornitori
- Una base giuridica per ogni trattamento (art. 6): contratto per ciò che serve al servizio (account, chat), consenso per ciò che è facoltativo (posizione, SOS, dati dell'art. 9, analytics non essenziali).
- DPIA (art. 35) prima del lancio e a ogni funzione nuova su posizione o dati dell'art. 9: il trattamento su larga scala di dati dell'art. 9 la richiede (art. 35(3)(b)) e le linee guida europee sulla DPIA (WP248) contano la posizione tra i dati ad alto rischio. In Italia controllare anche l'elenco del Garante dei trattamenti soggetti a DPIA (provvedimento n. 467 dell'11 ottobre 2018).
- Registro dei trattamenti (art. 30): l'esenzione sotto i 250 dipendenti non vale se il trattamento non è occasionale o include dati dell'art. 9.
- Contratto di trattamento (art. 28) con ogni fornitore che tocca dati personali: database e auth (Supabase), hosting (Render), email, mappe e geocoding, monitoraggio errori, analytics. Tutti elencati nell'informativa.
- Trasferimenti fuori dall'UE (artt. 44–49): regione UE per il progetto Supabase quando possibile; per i fornitori USA verificare la base (certificazione EU-US Data Privacy Framework o clausole contrattuali standard).
- Tempi di conservazione scritti per ogni dato e applicati da job automatici (art. 5(1)(e)). Esempio: presenza → alla scadenza; storie → 24 ore, file compresi; SOS → 72 ore; log con IP → 30 giorni.
- Violazione: notifica all'autorità di controllo entro 72 ore da quando se ne viene a conoscenza (art. 33), e agli utenti se il rischio è elevato (art. 34), come quasi sempre per posizioni o dati dell'art. 9. Procedura in risposta-incidenti.

### 11. Accesso, export e cancellazione
- Accesso ed export (artt. 15 e 20): una funzione che restituisce in JSON tutti i dati dell'utente (profilo, consensi, amicizie, messaggi inviati, gruppi) con link firmati e a scadenza ai suoi file. Risposta entro un mese (art. 12(3)).
- Cancellazione (art. 17): un'Edge Function (o un job su un server) con la chiave secret elimina l'utente da Auth; i suoi dati hanno `on delete cascade` verso `auth.users`. Eccezioni: segnalazioni, prove, azioni di moderazione e blocchi d'accesso usano `on delete set null` (o un id senza vincolo) e restano per un periodo scritto, per difendere le altre persone (art. 17(3)(e), art. 6(1)(f)); poi un job li cancella (sicurezza-social §2 e §7). I file di Storage non spariscono con le righe: cancellarli con l'API di Storage (`remove`), non con un `delete` su `storage.objects`, quindi senza un server serve almeno un'Edge Function.
- Decidere e scrivere cosa succede ai messaggi già inviati ad altri (cancellati o firmati "utente eliminato").
- I backup non si modificano: i dati restano fino alla rotazione del fornitore. Scriverne la durata nell'informativa e tenere l'elenco degli ID cancellati per ripetere la cancellazione dopo un ripristino.

### 12. Log e analytics senza posizioni
- Coordinate solo nel corpo delle richieste (le `rpc()` di `supabase-js` usano POST), mai nella query string: i log delle API registrano gli URL.
- Niente `console.log` di posizioni, profili o messaggi; togliere questi dati dagli strumenti di errore prima dell'invio (`beforeSend` in Sentry).
- Eventi di analytics senza coordinate, città piccole o valori dell'art. 9 (`gruppo_aggiunto`, non il nome del gruppo). Anche l'IP è una posizione approssimativa: troncarlo o non salvarlo.

## Checklist
Prima di consegnare verificare: posizione arrotondata da trigger e nessuno storico; nessuna API con distanze esatte, ordine fine o raggio libero; presenza opt-in, a scadenza, solo amici, con eccezioni e blocchi; sconosciuti solo a livello di città; mappe e geocoding a precisione ridotta e senza coordinate negli URL; foto e video senza GPS; SOS con consenso e cancellazione; art. 9 con consenso separato e visibilità per campo; età sì, data di nascita no; DPIA, registro, contratti con i fornitori, conservazione scritta; export e cancellazione completi, file compresi; log e analytics puliti.

## Limiti da comunicare
- La griglia nasconde il punto, non le abitudini: un amico che vede la stessa cella ogni sera capisce dove si abita. Per questo la condivisione è solo per amici, scade e si spegne con un tocco.
- La pulizia dei metadati non toglie ciò che si vede nella foto (insegne, targhe, vista dalla finestra).
- L'età dichiarata si può falsificare: la segnalazione resta necessaria.
- Questa skill non è una consulenza legale: informativa, basi giuridiche e DPIA vanno riviste da chi si occupa di protezione dei dati.

---

# Location and Sensitive Data Privacy (English)

In an app where people meet in person, location and sensitive data (orientation, religion, political views, health) do the most harm when they leak: stalking, outing, assault, burglary of an empty home. The rules of supabase-sicuro (RLS, grants, functions) and hardening-siti still apply; this skill says **how much** data to keep and **who** can derive it. Principle: the precision a user gets by combining every API (map, lists, filters, distances, notifications) must not exceed what you mean to show them.

## Mandatory rules

### 1. Collect the minimum
- For every field, write down what it is for; if no feature uses it, don't collect it. "Who is around" needs a cell of a few hundred metres; strangers need the city at most.
- No location history: one row per user, overwritten, expiring. History reveals home, work and routines.
- Ask the browser for location only when the user turns the feature on, with `enableHighAccuracy: false`. If the app uses it, `Permissions-Policy: geolocation=(self)` instead of `geolocation=()` (hardening-siti).

### 2. Round in the database, on a grid
- Rounding in the client protects nothing: anyone can call the API with exact coordinates. Round in a trigger before storing, so the raw value never exists.
- Use a fixed grid and store the **cell centre**. A fresh random offset on every read cancels out by averaging many reads; a fixed per-user offset is learned once (by meeting the person or knowing one of their addresses) and then holds forever. The grid always returns the same cell: repeated reads add nothing.
- Moving from one cell to the next reveals the border: switch cells only once the person is a quarter of a cell inside the new one (hysteresis).
- Outside cities 250 m can single out one house: larger cells where people are few, or just the locality name.
```sql
create function private.snap_cell() returns trigger
language plpgsql set search_path = '' as $$
declare
  dlat constant float8 := 0.00225;  -- ~250 m north-south
  dlng float8;
begin
  -- hysteresis: near the previous cell (less than a quarter into the new one) stay there
  if tg_op = 'UPDATE' and old.lat is not null
     and abs(new.lat - old.lat) < 0.75 * dlat
     and abs(new.lng - old.lng) < 0.75 * dlat / greatest(cos(radians(old.lat)), 0.2) then
    new.lat := old.lat; new.lng := old.lng;
    return new;
  end if;
  new.lat := (floor(new.lat / dlat) + 0.5) * dlat;           -- cell centre
  dlng := dlat / greatest(cos(radians(new.lat)), 0.2);       -- ~250 m east-west too
  new.lng := (floor(new.lng / dlng) + 0.5) * dlng;
  return new;
end $$;
create trigger snap_cell before insert or update of lat, lng on public.presence
  for each row execute function private.snap_cell();
```

### 3. No distance oracles
- Trilateration, documented on several dating apps: the attacker spoofs their own location, reads the distance from three points and finds the victim within a few metres. It works with rounded distances and "within X km" filters too, by searching for the point where the value flips.
- Never exact distances. Wide bands (`< 1 km`, `1–5 km`, `5–20 km`, `> 20 km`) computed between cell centres, never raw points. For strangers, city-to-city distance at most.
- Filter radii picked from a few fixed values, not a free number. No sorting by fine distance: sort by band, then by something unrelated to distance (activity, name).
- The searcher's location comes from the client and may be fake: round it like the others, reject impossible jumps (hundreds of km in a few minutes), rate-limit location changes and searches (difesa-attacchi).

### 4. Who sees what, and for how long
- Sharing off by default; it turns on with an explicit action and shows an indicator while active. Presence has an expiry (`expires_at`): the policy filters it, a job deletes it.
- Only friends see the cell; anyone can hide from individual friends; blocks work both ways and everywhere (map, lists, stories, groups). Strangers see the city at most.
- Travel mode: show strangers the destination city only during the trip, not before. Announcing it in advance also says the home is empty.
- Tables and events in public places may have the exact address; those at someone's home show only the area until the host accepts. Only participants see the participant list.
- Supabase Realtime: `postgres_changes` applies RLS to inserts and updates, but DELETE events reach every subscriber with the primary key: presence, block or friendship tables do not belong in the `supabase_realtime` publication. Broadcast and presence go through RLS only on private channels with policies on `realtime.messages`. No locations on public channels (details in supabase-sicuro).
- "Updated" rounded ("now", "today"), not to the second. Notifications ("X is nearby") use the band: they pass through Apple's and Google's servers and stay on the lock screen.
```sql
create policy "presence visible to friends" on public.presence for select to authenticated
using (expires_at > now() and (
  user_id = (select auth.uid())
  or private.can_see_presence(user_id)  -- security definer: friendship, not hidden, not blocked
));
select cron.schedule('expired-presence', '*/15 * * * *',
  $$delete from public.presence where expires_at < now()$$);
```

### 5. Third-party maps and geocoding
- Every tile or geocoding request hands the provider the user's IP, the `Referer` and, for tiles, area and zoom: someone who always looks at the same street at high zoom reveals where they live. Reverse geocoding sends the coordinates.
- Reverse geocode the cell centre, never the raw point; send at most 3 decimals (about 110 m) in searches.
- OpenStreetMap's public Nominatim has a usage policy: at most 1 request per second, no search-as-you-type, an identified application, attribution. Every request carries the user's IP to the OSM Foundation: search only on submit, go through your own proxy or host your own instance.
- Serve tiles yourself (e.g. a PMTiles file on your own storage or CDN) or through a proxy (Edge Function) that strips IP and cookies; otherwise a provider that does not profile, named in the privacy notice.
- `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer`) and only the needed domains in the CSP. Never coordinates in app URLs (`?lat=…&lng=…`): they end up in history, logs, analytics and `Referer`.

### 6. Photos and videos without GPS
- Phone photos often carry exact coordinates in EXIF. Redrawing them on a canvas before upload creates a new file with no metadata:
```js
async function withoutMetadata(file) {
  const img = await createImageBitmap(file);
  const canvas = new OffscreenCanvas(img.width, img.height);
  canvas.getContext('2d').drawImage(img, 0, 0);
  return canvas.convertToBlob({ type: 'image/jpeg', quality: 0.85 }); // no EXIF, no GPS
}
```
- The client can be bypassed: where possible repeat the cleanup server-side (Edge Function, image transformation) and spot-check stored files with `exiftool -gps:all <file>`.
- Videos keep the location in the container: accept them only with a server-side pass (`ffmpeg -i in.mp4 -map_metadata -1 -c copy out.mp4`).

### 7. SOS: the only exception
- Exact location only in an SOS, only to contacts the user chose, with explicit consent given when setting the feature up, not in the moment of danger.
- While active: an always-visible indicator, a button to stop it, automatic stop after a set time.
- Separate table with RLS (the user and the recipients read it), short written retention (e.g. 72 hours) with automatic deletion. Never in normal presence, logs or analytics.

### 8. GDPR art. 9 data
- Special categories (art. 9(1)): racial or ethnic origin, political opinions, religious or philosophical beliefs, trade union membership, genetic data, biometric data used to identify someone (e.g. face matching to verify a profile), health, sex life and sexual orientation. Gender identity is not named, but it can reveal orientation or health: treat it the same way.
- **Explicit consent** is required (art. 9(2)(a)): one unticked box per field, separate from the terms of service, saying who will see it. Store the date and the text version. Withdrawing must be as easy as consenting (art. 7(3)); withdrawal deletes the data.
- Fields always optional, with "prefer not to say". Per-field visibility (only me / friends / everyone), defaulting to the narrowest.
- Inferred data counts too: membership of an LGBTQ+ group, a parish or a party can reveal it. Members visible only to members; sensitive groups private by default.
- No searching or filtering strangers by these fields (that builds lists); no advertising or profiling without a separate consent.
- Beware of inference from counts and filters: an "LGBTQ+ only" table showing how many compatible people are nearby, narrowed until one person is left, reveals their orientation. Counts in bands with a minimum ("fewer than 10"), no count when place and attribute narrow it too far, rate limits; record it in the DPIA.

### 9. Age: 18+
- Check majority at sign-up in the database (trigger), not only in the form. Provide reporting for profiles that look like minors, with review and suspension.
- Others see only the age, never the birthdate: the date in a schema the API does not expose, the age from an internal function used by the RPCs that return a profile the caller may already see (respecting blocks and privacy). Callable by everyone, it would give anyone's age, even someone who blocked you.
```sql
create function private.age_of(uid uuid) returns int
language sql stable security definer set search_path = '' as $$
  select extract(year from age(b.birthdate))::int from private.birthdates b where b.user_id = uid
$$;
revoke execute on function private.age_of(uuid) from public, anon, authenticated;
```

### 10. GDPR: bases, records, providers
- A lawful basis for each processing (art. 6): contract for what the service needs (account, chat), consent for what is optional (location, SOS, art. 9 data, non-essential analytics).
- DPIA (art. 35) before launch and for every new feature touching location or art. 9 data: large-scale processing of art. 9 data requires it (art. 35(3)(b)) and the European DPIA guidelines (WP248) count location among high-risk data. In Italy also check the Garante's list of processing that requires a DPIA (decision no. 467 of 11 October 2018).
- Records of processing (art. 30): the under-250-employees exemption does not apply when processing is not occasional or includes art. 9 data.
- Processing agreement (art. 28) with every provider touching personal data: database and auth (Supabase), hosting (Render), email, maps and geocoding, error monitoring, analytics. All named in the privacy notice.
- Transfers outside the EU (arts. 44–49): an EU region for the Supabase project when possible; for US providers check the basis (EU-US Data Privacy Framework certification or standard contractual clauses).
- Written retention periods for every field, enforced by scheduled jobs (art. 5(1)(e)). Example: presence → at expiry; stories → 24 hours, files included; SOS → 72 hours; logs with IPs → 30 days.
- Breach: notify the supervisory authority within 72 hours of becoming aware (art. 33), and users when the risk is high (art. 34), as it almost always is for locations or art. 9 data. Procedure in risposta-incidenti.

### 11. Access, export and erasure
- Access and export (arts. 15 and 20): a function returning all the user's data as JSON (profile, consents, friendships, sent messages, groups) with signed, expiring links to their files. Answer within one month (art. 12(3)).
- Erasure (art. 17): an Edge Function (or a server job) with the secret key deletes the user from Auth; their data has `on delete cascade` to `auth.users`. Exceptions: reports, evidence, moderation actions and access bans use `on delete set null` (or an id without a foreign key) and are kept for a written period, to protect other people (art. 17(3)(e), art. 6(1)(f)); then a job deletes them (sicurezza-social §2 and §7). Storage files do not vanish with the rows: delete them with the Storage API (`remove`), not with a `delete` on `storage.objects`, so without a server you need at least an Edge Function.
- Decide and write down what happens to messages already sent to others (deleted, or signed "deleted user").
- Backups cannot be edited: data stays until the provider rotates them. State that period in the privacy notice and keep a list of deleted IDs to repeat the deletion after a restore.

### 12. Logs and analytics without locations
- Coordinates only in request bodies (`supabase-js` `rpc()` uses POST), never in the query string: API logs record URLs.
- No `console.log` of locations, profiles or messages; strip them from error tools before sending (`beforeSend` in Sentry).
- Analytics events without coordinates, small towns or art. 9 values (`group_joined`, not the group's name). An IP is an approximate location too: truncate it or don't store it.

## Checklist
Before delivery verify: location rounded by a trigger and no history; no API with exact distances, fine ordering or free radius; presence opt-in, expiring, friends only, with exceptions and blocks; strangers at city level only; maps and geocoding at reduced precision and no coordinates in URLs; photos and videos without GPS; SOS with consent and deletion; art. 9 with separate consent and per-field visibility; age yes, birthdate no; DPIA, records, provider agreements, written retention; complete export and erasure, files included; clean logs and analytics.

## Limits to communicate
- The grid hides the point, not the routine: a friend who sees the same cell every night works out where you live. That is why sharing is friends-only, expires and turns off with one tap.
- Stripping metadata does not remove what the photo shows (signs, number plates, the view from a window).
- A declared age can be faked: reporting stays necessary.
- This skill is not legal advice: the privacy notice, lawful bases and DPIA must be reviewed by someone who handles data protection.
