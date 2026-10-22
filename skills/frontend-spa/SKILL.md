---
name: frontend-spa
description: Sicurezza delle app a pagina singola e dei siti statici (React, Vite, Vue, Svelte) - CSP senza script inline, punti di XSS, link sicuri, token nel browser, variabili pubbliche, source map, service worker, dipendenze. Trigger - "React", "Vite", "SPA", "CSP", "XSS", "dangerouslySetInnerHTML", "sito statico", "localStorage token". EN - Security of single-page apps and static sites (React, Vite, Vue, Svelte) - CSP without inline scripts, XSS sinks, safe links, tokens in the browser, public env vars, source maps, service workers, dependencies. Triggers - "React", "Vite", "SPA", "CSP", "XSS", "dangerouslySetInnerHTML", "static site", "localStorage token".
---

# Frontend e SPA sicuri · Secure Front-end and SPAs

> 🇮🇹 Versione italiana qui sotto · 🇬🇧 [English version below](#secure-front-end-and-spas-english)

In una single-page app su hosting statico (React, Vite, Vue, Svelte) non c'è un server dell'app: tutto il codice gira nel browser, chiunque può leggerlo, e i dati sono protetti solo dalle regole del backend (supabase-sicuro, api-sicura). Il frontend ha un compito suo: non far girare codice altrui nella pagina. Con Supabase JS la sessione sta in `localStorage`, quindi **un XSS equivale a prendersi l'account**: lo script dell'attaccante legge il refresh token e lo usa da un altro computer. Header generali e HTTPS sono in hardening-siti; qui c'è ciò che è specifico dei frontend statici.

## Regole obbligatorie

### 1. CSP stretta, senza script inline
- Su un hosting statico i nonce sono impossibili (serve un valore nuovo a ogni risposta) e gli hash vanno ricalcolati a ogni build. La via semplice: **nessuno script inline**, solo file esterni e `script-src 'self'`. Lo script che applica il tema prima del primo disegno va in un file (`/theme-init.js`) caricato nel `<head>`.
- Mai `'unsafe-inline'` o `'unsafe-eval'` in `script-src`: una libreria che chiede `eval` si cambia o si usa precompilata. Per WebAssembly basta `'wasm-unsafe-eval'`. `'unsafe-inline'` in `style-src` è accettabile solo se una libreria inserisce tag `<style>`; gli stili di React (`style={{…}}`) passano comunque.
- `connect-src` con domini esatti, mai `https:` o `*.supabase.co`: il secondo lascia spedire i dati rubati al progetto Supabase dell'attaccante. Le mappe caricano tile, stili e glifi con `fetch` (quindi `connect-src`) e spesso avviano worker da `blob:`.
- `img-src` solo dai propri domini: un'immagine con URL scelto da un utente fa chiamare a ogni lettore il server dell'attaccante, che riceve l'IP (cioè la zona). Esempio per React + Supabase + mappa:
```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob: https://REF.supabase.co;
connect-src 'self' https://REF.supabase.co wss://REF.supabase.co https://tiles.openfreemap.org;
worker-src 'self' blob:; font-src 'self'; manifest-src 'self'; frame-src 'none'; object-src 'none';
base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests; report-to csp
```
- `report-to csp` vuole l'header `Reporting-Endpoints: csp="https://…"` (un servizio di raccolta o una Edge Function con limite di frequenza); aggiungere `report-uri` per i browser che non supportano `report-to`. Una policy nuova va prima pubblicata come `Content-Security-Policy-Report-Only` per una settimana, leggendo i rapporti. In locale, la stessa CSP in `preview.headers` di `vite.config` mostra gli errori con `vite preview`. Il tag `<meta http-equiv>` ignora `frame-ancestors`, `report-uri` e `sandbox`: solo dove l'hosting non permette header.

### 2. Header sull'hosting statico
- Gli header stanno nel file della piattaforma, versionato con il codice, e devono valere anche per la riscrittura SPA (`/*` → `/index.html`). Render (`render.yaml`):
```yaml
    headers:
      - path: /*
        name: Content-Security-Policy
        value: "default-src 'self'; script-src 'self'; …"
```
- Netlify: `public/_headers` con la riga `/*` e sotto, indentato, `Content-Security-Policy: …`. Vercel: `vercel.json` con `{"headers":[{"source":"/(.*)","headers":[{"key":"Content-Security-Policy","value":"…"}]}]}`.
- `index.html` con `Cache-Control: no-cache`, così una correzione arriva a tutti al caricamento successivo; i file con hash in `/assets/*` con `public, max-age=31536000, immutable`.
- Con la CSP: `X-Frame-Options: DENY`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `Referrer-Policy` e `Permissions-Policy` con solo ciò che l'app usa (`geolocation=(self)` per la mappa degli amici, `camera=(self)` per le storie, il resto `()`) (hardening-siti).

### 3. Punti di iniezione (sink)
- React fa l'escape del testo in JSX. Le eccezioni vanno cercate a ogni revisione: `dangerouslySetInnerHTML`, `ref.current.innerHTML`, `insertAdjacentHTML`, `document.write`, `eval`/`new Function`/`setTimeout("…")`, `location.href = …`; negli altri framework `v-html`, `{@html}`, `bypassSecurityTrust…`. Le regole ESLint `react/no-danger` e `no-restricted-properties` (su `innerHTML`, `outerHTML`) segnalano quelli nuovi nella CI.
- Le librerie non React scrivono HTML: popup delle mappe (`popup.setHTML()` in MapLibre e Mapbox, `bindPopup("…")` in Leaflet), tooltip dei grafici con formatter che restituiscono HTML, toast. Nomi di tavoli, eventi, gruppi e profili si passano come testo:
```js
const el = document.createElement('div');
el.textContent = evento.titolo;  // testo, mai HTML
new maplibregl.Popup().setDOMContent(el).setLngLat(pos).addTo(map);
```
- Se una libreria accetta solo HTML, il testo passa da una funzione di escape condivisa, mai da concatenazioni a mano:
```js
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
```

### 4. URL e CSS scritti dagli utenti
- Un `href` scelto da un utente (sito nel profilo, link in chat) può essere `javascript:`. Non contare sul framework: controllare lo schema con il parser e accettare solo `https:` e `mailto:`. Per gli URL mai regex o `startsWith('http')`. Lo stesso per `src`, `window.open` e `location.assign`.
```js
export function urlSicuro(raw) {
  try { const u = new URL(raw); return ['https:', 'mailto:'].includes(u.protocol) ? u.href : null; }
  catch { return null; }
}
```
- Link esterni con `target="_blank" rel="noopener noreferrer"` (contenuti degli utenti: anche `nofollow ugc`). Immagini, video e audio degli utenti solo dal proprio Storage, mai URL esterni liberi. Iframe con URL degli utenti: mai.
- Mai CSS libero degli utenti in `style` o in un tag `<style>`: può coprire l'interfaccia con un finto modulo di accesso o leggere attributi con i selettori. Colori e temi da un elenco o da un formato controllato (`/^#[0-9a-f]{6}$/i`).

### 5. Markdown, HTML degli utenti e Trusted Types
- `react-markdown` senza `rehype-raw` non rende l'HTML grezzo; se serve, aggiungere `rehype-sanitize`. Con librerie che producono una stringa (`marked`, `markdown-it`) sanificare con DOMPurify al momento di mostrarla, non solo al salvataggio, perché il dato può essere stato scritto chiamando l'API direttamente: `DOMPurify.sanitize(marked.parse(testo), { USE_PROFILES: { html: true } })`. Aggiornare DOMPurify spesso: le versioni nuove chiudono aggiramenti.
- Trusted Types (`require-trusted-types-for 'script'; trusted-types dompurify`) fa rifiutare al browser le stringhe passate a `innerHTML` e simili che non arrivano da una policy dichiarata. È supportato almeno dai browser basati su Chromium; dove manca la direttiva viene ignorata. Provarlo prima in `Report-Only`: le librerie che usano `innerHTML` compaiono nei rapporti. DOMPurify con `RETURN_TRUSTED_TYPE: true` usa la sua policy `dompurify`. Attenzione: MapLibre crea il suo worker da un URL `blob:`, che per Trusted Types è un punto da proteggere: tenere TT in `Report-Only` oppure aggiungere una policy `default` stretta che accetta solo URL `blob:`.

### 6. Token e sessioni nel browser
- `localStorage` (default di Supabase JS, chiave `sb-<ref>-auth-token`): qualunque script nella pagina legge access e refresh token e li usa altrove. Cookie `HttpOnly`: lo script non li legge, ma un XSS agisce come l'utente finché la pagina è aperta, e servono un server o una funzione sul proprio dominio che li impostino. In entrambi i casi la difesa vera è l'assenza di XSS.
- Con Supabase: `createClient(url, key, { auth: { flowType: 'pkce' } })` (il codice nell'URL non serve senza il verificatore salvato nel browser; nel flusso implicito i token arrivano nell'URL), rilevamento dei refresh token riusati attivo, durata e inattività delle sessioni limitate dove il piano lo permette, "esci da tutti i dispositivi" con `signOut({ scope: 'global' })`.
- Più account salvati per il cambio rapido moltiplicano il danno: un XSS li prende tutti. Tenerne pochi, togliere quelli non usati da settimane, richiedere l'accesso dopo un periodo. Cifrarli nel browser non serve: lo script dell'attaccante gira nella stessa origine e decifra.
- All'uscita cancellare tutto ciò che resta sul dispositivo: sessione, cache delle query salvate, IndexedDB dei messaggi, Cache Storage. Mai token negli URL, nei log, negli eventi di analytics o negli errori inviati ai servizi di monitoraggio.

### 7. Il bundle è pubblico
- Tutto ciò che entra nel build si legge: variabili `VITE_*` (e `NEXT_PUBLIC_*`, `PUBLIC_*`, `VUE_APP_*`), costanti, rotte "admin". Nel frontend solo chiavi pubblicabili: Supabase `sb_publishable_…`, chiavi di mappe limitate al dominio nella console del fornitore. Mai `sb_secret_…`/`service_role`, chiavi Stripe `sk_…`, token di servizi email o di AI: vanno in Edge Functions (api-sicura).
- Mai `define: { 'process.env': process.env }` in `vite.config` né `envPrefix` allargati: mettono nel bundle tutto l'ambiente di build. Nascondere una pagina nel client non è un controllo d'accesso: il permesso si verifica nel database o nella funzione.
- Source map: `build.sourcemap: false`, oppure `'hidden'` per inviarle al servizio di errori e poi **cancellarle da `dist/`**: `hidden` toglie solo il riferimento, i file restano scaricabili.
- Un segreto pubblicato anche una volta si ruota subito (risposta-incidenti): restano copie in cache e negli archivi. Chi entra nell'account dell'hosting o di npm pubblica il JS che vuole: 2FA ovunque (account-fornitori).

### 8. Script di terzi, SRI, analytics
- Ogni script di terzi ha i poteri del vostro codice, token compresi. Preferire pacchetti npm inclusi nel build a script da CDN; font serviti da sé (ogni richiesta a un CDN di font porta l'IP dell'utente al fornitore). Captcha: solo il dominio del fornitore (Turnstile: `https://challenges.cloudflare.com` in `script-src` e `frame-src`).
- Uno script esterno inevitabile ha versione fissa e hash: `<script src="https://cdn.example.com/lib@1.2.3/lib.min.js" integrity="sha384-…" crossorigin="anonymous">`, con l'hash da `openssl dgst -sha384 -binary lib.min.js | openssl base64 -A`. Gli script che cambiano da soli (loader di analytics, widget di chat, tag manager) non possono avere SRI: fuori dalle pagine con sessione, o niente.
- Analytics senza cookie e senza dati personali dove possibile, server nell'UE o proprio; consenso per ciò che non è indispensabile (direttiva ePrivacy, art. 5(3)). Togliere query e frammento dagli URL inviati (codici di invito, `?code=`), niente ID utente in chiaro, posizioni o dati dell'art. 9 GDPR (privacy-posizione).

### 9. Redirect, postMessage, clickjacking
- `?next=` e simili: solo percorsi della propria origine, controllati con il parser (`//evil.com` e `/\evil.com` sembrano relativi ma non lo sono). I `redirectTo` di Supabase Auth vanno anche negli URL consentiti (supabase-sicuro).
```js
export function nextSicuro(raw, fallback = '/') {
  try { const u = new URL(raw ?? fallback, location.origin);
        return u.origin === location.origin ? u.pathname + u.search + u.hash : fallback; }
  catch { return fallback; }
}
```
- `postMessage`: chi riceve confronta `event.origin` con un valore esatto e controlla la forma dei dati; chi invia indica l'origine di destinazione, mai `'*'` con dati privati.
- Clickjacking: `frame-ancestors 'none'` più `X-Frame-Options: DENY`; se l'app va incorporata, solo domini esatti. Le azioni gravi (cancellare l'account, condividere la posizione, SOS) chiedono comunque una conferma.

### 10. Service worker e PWA
- Il service worker intercetta le richieste del suo ambito e resta installato dopo la chiusura: un errore (risposte private in cache, file vecchi serviti per sempre) sopravvive al rilascio della correzione. Si registra solo da un file della propria origine: niente file degli utenti sul dominio dell'app, niente header `Service-Worker-Allowed` largo.
- Precache solo dei file del build con hash, mai `.map`; in cache solo risposte 200. Mai risposte autenticate: API di Supabase (`/rest/v1`, `/auth/v1`, URL firmati di `/storage/v1`) e richieste con `Authorization`. Con `vite-plugin-pwa`: niente `runtimeCaching` su quei domini, `injectRegister: 'script'` (file esterno, non `'inline'`).
- Tenere pronto un worker che si disattiva da solo, da pubblicare se uno difettoso è in giro:
```js
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(caches.keys()
  .then((ks) => Promise.all(ks.map((k) => caches.delete(k)))).then(() => self.registration.unregister())));
```

### 11. Dipendenze del frontend
- Il codice delle dipendenze entra nel bundle e gira con la sessione dell'utente. A settembre 2025 versioni compromesse di pacchetti molto usati (fra cui `chalk` e `debug`) sono rimaste pubblicate per alcune ore con codice pensato per il browser, che dirottava pagamenti in criptovalute. Nello stesso mese il worm "Shai-Hulud" si è propagato da pacchetto a pacchetto rubando i token npm e GitHub dalle macchine degli sviluppatori: `npm ci --ignore-scripts` dove possibile, token npm con scadenza e solo dove servono, qualche giorno di attesa prima di adottare una versione appena pubblicata.
- Lockfile nella repo; `npm ci` nella CI e nel comando di build dell'hosting (`npm ci && npm run build`), mai `npm install`. `npm audit --omit=dev --audit-level=high` nella CI. Le dipendenze di sviluppo non entrano nel bundle ma girano sulla macchina di build, con i suoi segreti: si aggiornano anche quelle.
- Prima di aggiungere un pacchetto: rilasci recenti, manutentori noti, repository non archiviato, nessun avviso `deprecated`. Per piccole funzioni le API del browser (`URL`, `Intl`, `crypto.randomUUID()`, `structuredClone`). Una dipendenza indiretta vulnerabile si forza con `overrides` (`npm ls <pacchetto>` dice chi la porta). Automazione: sicurezza-github.

## Checklist
Controllo prima del rilascio (ogni comando di ricerca deve restituire niente, salvo l'ultimo `grep`, da rivedere a mano):
```sh
npm ci && npm run build && npm audit --omit=dev --audit-level=high
find dist -name '*.map'
grep -rEn 'sb_secret_|sk_live_|rk_live_|BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}' dist
grep -rhoE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+' dist | sort -u | while read -r t; do
  echo "${t#*.}" | tr '_-' '/+' | base64 -d 2>/dev/null; echo; done | grep service_role
grep -nP '<script(?![^>]*\bsrc=)' dist/*.html
curl -sI https://app.example.com/percorso/profondo | grep -icE 'content-security-policy|strict-transport|x-frame|nosniff|referrer-policy|permissions-policy'  # 6
curl -s https://app.example.com/assets/index-HASH.js.map | head -c 15  # non deve iniziare con {"version":3 (gli host SPA rispondono 200 con index.html ai file mancanti)
grep -rnE 'dangerouslySetInnerHTML|innerHTML|insertAdjacentHTML|setHTML\(|v-html|\{@html' src
```
Poi: console del browser senza violazioni CSP sulle pagine principali; Mozilla HTTP Observatory e CSP Evaluator di Google senza avvisi gravi; script di terzi, `next`, `postMessage` e service worker ricontrollati se toccati.

## Limiti da comunicare
- La CSP riduce i danni di un XSS, non lo elimina: un'iniezione che usa solo codice già presente (un `href` non filtrato) passa comunque. Sink puliti e CSP servono insieme.
- Nel browser non c'è modo di proteggere i token in `localStorage` da uno script che gira nella pagina; i cookie `HttpOnly` richiedono un server sul proprio dominio, e anche con quelli un XSS agisce come l'utente.
- Il frontend si legge e si modifica: ogni controllo nel client è comodità, la sicurezza dei dati sta nel backend (supabase-sicuro, api-sicura).
- Trusted Types e `report-to` non sono supportati da tutti i browser: sono un livello in più. Gli header dipendono dall'hosting: ricontrollarli con `curl -I` dopo ogni cambio di piattaforma o di configurazione.

---

# Secure Front-end and SPAs (English)

In a single-page app on static hosting (React, Vite, Vue, Svelte) there is no app server: all the code runs in the browser, anyone can read it, and the data is protected only by the backend rules (supabase-sicuro, api-sicura). The front-end has its own job: never let someone else's code run in the page. With Supabase JS the session lives in `localStorage`, so **an XSS is an account takeover**: the attacker's script reads the refresh token and uses it from another computer. General headers and HTTPS are in hardening-siti; this skill covers what is specific to static front-ends.

## Mandatory rules

### 1. A strict CSP, no inline scripts
- On static hosting nonces are impossible (each response needs a fresh value) and hashes must be recomputed on every build. The simple way: **no inline scripts**, external files only and `script-src 'self'`. The script that applies the theme before first paint goes in a file (`/theme-init.js`) loaded in `<head>`.
- Never `'unsafe-inline'` or `'unsafe-eval'` in `script-src`: a library that needs `eval` gets replaced or used precompiled. WebAssembly only needs `'wasm-unsafe-eval'`. `'unsafe-inline'` in `style-src` is acceptable only if a library injects `<style>` tags; React styles (`style={{…}}`) work anyway.
- `connect-src` with exact domains, never `https:` or `*.supabase.co`: the latter lets stolen data be sent to the attacker's own Supabase project. Maps load tiles, styles and glyphs with `fetch` (so `connect-src`) and often start workers from `blob:`.
- `img-src` only from your own domains: an image whose URL a user chose makes every viewer call the attacker's server, which gets their IP (that is, their area). Example for React + Supabase + a map:
```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob: https://REF.supabase.co;
connect-src 'self' https://REF.supabase.co wss://REF.supabase.co https://tiles.openfreemap.org;
worker-src 'self' blob:; font-src 'self'; manifest-src 'self'; frame-src 'none'; object-src 'none';
base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests; report-to csp
```
- `report-to csp` needs the header `Reporting-Endpoints: csp="https://…"` (a collection service or a rate-limited Edge Function); add `report-uri` for browsers without `report-to`. Ship a new policy as `Content-Security-Policy-Report-Only` for a week first, reading the reports. Locally, the same CSP in `preview.headers` of `vite.config` shows the errors under `vite preview`. The `<meta http-equiv>` tag ignores `frame-ancestors`, `report-uri` and `sandbox`: only where the host allows no headers.

### 2. Headers on static hosting
- Headers live in the platform's file, versioned with the code, and must also apply to the SPA rewrite (`/*` → `/index.html`). Render (`render.yaml`):
```yaml
    headers:
      - path: /*
        name: Content-Security-Policy
        value: "default-src 'self'; script-src 'self'; …"
```
- Netlify: `public/_headers` with a `/*` line and, indented below it, `Content-Security-Policy: …`. Vercel: `vercel.json` with `{"headers":[{"source":"/(.*)","headers":[{"key":"Content-Security-Policy","value":"…"}]}]}`.
- `index.html` with `Cache-Control: no-cache`, so a fix reaches everyone on the next load; hashed files in `/assets/*` with `public, max-age=31536000, immutable`.
- Alongside the CSP: `X-Frame-Options: DENY`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `Referrer-Policy` and a `Permissions-Policy` with only what the app uses (`geolocation=(self)` for the friends map, `camera=(self)` for stories, the rest `()`) (hardening-siti).

### 3. Injection points (sinks)
- React escapes text in JSX. The exceptions must be searched for in every review: `dangerouslySetInnerHTML`, `ref.current.innerHTML`, `insertAdjacentHTML`, `document.write`, `eval`/`new Function`/`setTimeout("…")`, `location.href = …`; in other frameworks `v-html`, `{@html}`, `bypassSecurityTrust…`. The ESLint rules `react/no-danger` and `no-restricted-properties` (on `innerHTML`, `outerHTML`) flag new ones in CI.
- Non-React libraries write HTML: map popups (`popup.setHTML()` in MapLibre and Mapbox, `bindPopup("…")` in Leaflet), chart tooltips whose formatters return HTML, toasts. Names of tables, events, groups and profiles go in as text:
```js
const el = document.createElement('div');
el.textContent = event.title;  // text, never HTML
new maplibregl.Popup().setDOMContent(el).setLngLat(pos).addTo(map);
```
- If a library only accepts HTML, the text goes through one shared escape function, never hand-made concatenation:
```js
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
```

### 4. User-supplied URLs and CSS
- An `href` chosen by a user (profile website, chat link) can be `javascript:`. Don't rely on the framework: check the scheme with the URL parser and accept only `https:` and `mailto:`. For URLs, never regexes or `startsWith('http')`. The same for `src`, `window.open` and `location.assign`.
```js
export function safeUrl(raw) {
  try { const u = new URL(raw); return ['https:', 'mailto:'].includes(u.protocol) ? u.href : null; }
  catch { return null; }
}
```
- External links with `target="_blank" rel="noopener noreferrer"` (user content: also `nofollow ugc`). User images, video and audio only from your own Storage, never free external URLs. Iframes with user URLs: never.
- Never free user CSS in `style` or a `<style>` tag: it can cover the UI with a fake sign-in form or read attributes through selectors. Colours and themes from a list or a checked format (`/^#[0-9a-f]{6}$/i`).

### 5. Markdown, user HTML and Trusted Types
- `react-markdown` without `rehype-raw` does not render raw HTML; if you need it, add `rehype-sanitize`. With libraries that produce a string (`marked`, `markdown-it`), sanitize with DOMPurify when displaying, not only on save, because the data may have been written by calling the API directly: `DOMPurify.sanitize(marked.parse(text), { USE_PROFILES: { html: true } })`. Update DOMPurify often: new releases close bypasses.
- Trusted Types (`require-trusted-types-for 'script'; trusted-types dompurify`) makes the browser reject strings passed to `innerHTML` and similar sinks unless they come from a declared policy. It is supported at least by Chromium-based browsers; where missing, the directive is ignored. Try it in `Report-Only` first: libraries using `innerHTML` show up in the reports. DOMPurify with `RETURN_TRUSTED_TYPE: true` uses its own `dompurify` policy. Beware: MapLibre creates its worker from a `blob:` URL, a Trusted Types sink: keep TT in `Report-Only` or add a narrow `default` policy that only accepts `blob:` URLs.

### 6. Tokens and sessions in the browser
- `localStorage` (the Supabase JS default, key `sb-<ref>-auth-token`): any script in the page reads the access and refresh tokens and uses them elsewhere. `HttpOnly` cookies: scripts cannot read them, but an XSS acts as the user while the page is open, and they need a server or function on your own domain to set them. Either way, the real defense is having no XSS.
- With Supabase: `createClient(url, key, { auth: { flowType: 'pkce' } })` (the code in the URL is useless without the verifier stored in the browser; in the implicit flow the tokens arrive in the URL), detection of reused refresh tokens on, session lifetime and inactivity limits where the plan allows, "sign out everywhere" with `signOut({ scope: 'global' })`.
- Several saved accounts for quick switching multiply the damage: one XSS takes them all. Keep few, drop those unused for weeks, require signing in again after a period. Encrypting them in the browser doesn't help: the attacker's script runs in the same origin and decrypts.
- On sign-out, delete everything left on the device: session, persisted query cache, message IndexedDB, Cache Storage. Never tokens in URLs, logs, analytics events or errors sent to monitoring services.

### 7. The bundle is public
- Everything in the build can be read: `VITE_*` variables (and `NEXT_PUBLIC_*`, `PUBLIC_*`, `VUE_APP_*`), constants, "admin" routes. Only publishable keys in the front-end: Supabase `sb_publishable_…`, map keys restricted to your domain in the provider's console. Never `sb_secret_…`/`service_role`, Stripe `sk_…` keys, email or AI service tokens: they belong in Edge Functions (api-sicura).
- Never `define: { 'process.env': process.env }` in `vite.config` nor a widened `envPrefix`: they put the whole build environment in the bundle. Hiding a page in the client is not access control: the permission is checked in the database or the function.
- Source maps: `build.sourcemap: false`, or `'hidden'` to upload them to the error service and then **delete them from `dist/`**: `hidden` only drops the reference, the files stay downloadable.
- A secret published even once is rotated at once (risposta-incidenti): copies remain in caches and archives. Whoever gets into the hosting or npm account ships whatever JS they like: 2FA everywhere (account-fornitori).

### 8. Third-party scripts, SRI, analytics
- Every third-party script has your code's powers, tokens included. Prefer npm packages bundled in the build over CDN scripts; self-host fonts (every request to a font CDN hands the user's IP to the provider). Captchas: only the provider's domain (Turnstile: `https://challenges.cloudflare.com` in `script-src` and `frame-src`).
- An unavoidable external script gets a pinned version and a hash: `<script src="https://cdn.example.com/lib@1.2.3/lib.min.js" integrity="sha384-…" crossorigin="anonymous">`, with the hash from `openssl dgst -sha384 -binary lib.min.js | openssl base64 -A`. Scripts that change on their own (analytics loaders, chat widgets, tag managers) cannot have SRI: keep them off signed-in pages, or drop them.
- Analytics without cookies or personal data where possible, servers in the EU or your own; consent for anything not strictly necessary (ePrivacy Directive, art. 5(3)). Strip query and fragment from reported URLs (invite codes, `?code=`), no plain user IDs, locations or GDPR art. 9 data (privacy-posizione).

### 9. Redirects, postMessage, clickjacking
- `?next=` and the like: only paths on your own origin, checked with the parser (`//evil.com` and `/\evil.com` look relative but are not). Supabase Auth `redirectTo` values also go in the allowed URLs (supabase-sicuro).
```js
export function safeNext(raw, fallback = '/') {
  try { const u = new URL(raw ?? fallback, location.origin);
        return u.origin === location.origin ? u.pathname + u.search + u.hash : fallback; }
  catch { return fallback; }
}
```
- `postMessage`: the receiver compares `event.origin` with an exact value and checks the data's shape; the sender names the target origin, never `'*'` with private data.
- Clickjacking: `frame-ancestors 'none'` plus `X-Frame-Options: DENY`; if the app must be embedded, exact domains only. Serious actions (deleting the account, sharing location, SOS) still ask for confirmation.

### 10. Service workers and PWAs
- A service worker intercepts the requests in its scope and stays installed after the page closes: a bug (private responses cached, old files served forever) outlives the release of the fix. It can only be registered from a file on your own origin: no user files on the app's domain, no broad `Service-Worker-Allowed` header.
- Precache only hashed build files, never `.map`; cache only 200 responses. Never authenticated responses: Supabase APIs (`/rest/v1`, `/auth/v1`, signed `/storage/v1` URLs) and requests with `Authorization`. With `vite-plugin-pwa`: no `runtimeCaching` on those domains, `injectRegister: 'script'` (an external file, not `'inline'`).
- Keep a self-disabling worker ready, to ship if a faulty one is out there:
```js
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(caches.keys()
  .then((ks) => Promise.all(ks.map((k) => caches.delete(k)))).then(() => self.registration.unregister())));
```

### 11. Front-end dependencies
- Dependency code ends up in the bundle and runs with the user's session. In September 2025 compromised versions of widely used packages (including `chalk` and `debug`) stayed published for a few hours with code built for the browser that diverted cryptocurrency payments. The same month the "Shai-Hulud" worm spread from package to package, stealing npm and GitHub tokens from developers' machines: `npm ci --ignore-scripts` where possible, npm tokens that expire and only where needed, a few days' wait before adopting a freshly published version.
- Lockfile in the repo; `npm ci` in CI and in the host's build command (`npm ci && npm run build`), never `npm install`. `npm audit --omit=dev --audit-level=high` in CI. Dev dependencies don't enter the bundle but run on the build machine, with its secrets: keep them updated too.
- Before adding a package: recent releases, known maintainers, repository not archived, no `deprecated` warning. For small tasks, browser APIs (`URL`, `Intl`, `crypto.randomUUID()`, `structuredClone`). Force a patched transitive dependency with `overrides` (`npm ls <package>` shows who pulls it in). Automation: sicurezza-github.

## Checklist
Pre-release check (every search command must return nothing, except the last `grep`, which you review by hand):
```sh
npm ci && npm run build && npm audit --omit=dev --audit-level=high
find dist -name '*.map'
grep -rEn 'sb_secret_|sk_live_|rk_live_|BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}' dist
grep -rhoE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+' dist | sort -u | while read -r t; do
  echo "${t#*.}" | tr '_-' '/+' | base64 -d 2>/dev/null; echo; done | grep service_role
grep -nP '<script(?![^>]*\bsrc=)' dist/*.html
curl -sI https://app.example.com/deep/path | grep -icE 'content-security-policy|strict-transport|x-frame|nosniff|referrer-policy|permissions-policy'  # 6
curl -s https://app.example.com/assets/index-HASH.js.map | head -c 15  # must not start with {"version":3 (SPA hosts answer missing files with 200 and index.html)
grep -rnE 'dangerouslySetInnerHTML|innerHTML|insertAdjacentHTML|setHTML\(|v-html|\{@html' src
```
Then: browser console free of CSP violations on the main pages; Mozilla HTTP Observatory and Google's CSP Evaluator without serious warnings; third-party scripts, `next`, `postMessage` and the service worker re-checked if touched.

## Limits to communicate
- A CSP reduces the damage of an XSS, it does not remove it: an injection that only uses code already present (an unfiltered `href`) still works. Clean sinks and a CSP are needed together.
- In the browser there is no way to protect tokens in `localStorage` from a script running in the page; `HttpOnly` cookies need a server on your own domain, and even with them an XSS acts as the user.
- The front-end can be read and modified: every client-side check is convenience, data security lives in the backend (supabase-sicuro, api-sicura).
- Trusted Types and `report-to` are not supported by every browser: they are an extra layer. Headers depend on the host: re-check them with `curl -I` after any platform or configuration change.
