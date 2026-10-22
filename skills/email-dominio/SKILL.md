---
name: email-dominio
description: Sicurezza del dominio e delle email - account del registrar, DNSSEC, record CAA, sottodomini dimenticati, SPF, DKIM e DMARC per le email automatiche, contenuti sicuri delle email, difesa dal phishing a tuo nome, monitoraggio. Trigger - "dominio", "DNS", "SPF", "DKIM", "DMARC", "email transazionali", "phishing", "CAA". EN - Domain and email security - registrar account, DNSSEC, CAA records, dangling subdomains, SPF, DKIM and DMARC for transactional mail, safe email content, protection from phishing in your name, monitoring. Triggers - "domain", "DNS", "SPF", "DKIM", "DMARC", "transactional email", "phishing", "CAA".
---

# Dominio ed email · Domain and Email Security

> 🇮🇹 Versione italiana qui sotto · 🇬🇧 [English version below](#domain-and-email-security-english)

Chi controlla il dominio controlla il sito, le email di accesso degli utenti e i reset delle password di tutte le console. Le email dell'app (codici, conferme, avvisi) sono anche la prima cosa che i truffatori imitano. Questa skill copre registrar, DNS, certificati, autenticazione e contenuto delle email, caselle e monitoraggio. Collegate: account-fornitori (account delle console), hardening-siti (HTTPS e header), autenticazione-sicura (codici e verifica nel login), risposta-incidenti (dominio rubato o email false in corso). Negli esempi `example.com` è il vostro dominio e `provider.example` un fornitore: usare i valori che danno i fornitori.

## Regole obbligatorie

### 1. Account del registrar e del DNS
- 2FA con app o passkey, mai SMS; due amministratori o codici di recupero offline (account-fornitori). Lo stesso sul servizio DNS se è diverso dal registrar; i suoi token API limitati alla zona e, dove basta, in sola lettura.
- Blocco del trasferimento attivo (stato `clientTransferProhibited`); per il dominio principale anche il registry lock, se il registrar lo offre: ogni cambio di nameserver o contatti richiede una verifica fuori banda. Il codice di trasferimento (auth code) si chiede solo quando serve.
- Rinnovo automatico attivo, carta valida, rinnovo per più anni; avvisi attivi su cambi di nameserver, contatti e record.
- Email dell'account e del titolare su un **altro dominio** (un indirizzo con 2FA presso un altro fornitore): se il dominio scade o viene dirottato, la posta a `@example.com` non arriva più, o arriva all'attaccante, e con lei il reset del registrar.
- Controllo: `whois example.com | grep -iE 'status|expir'`.

### 2. DNSSEC
- Attivarlo se registrar e DNS lo supportano: firma della zona sul servizio DNS, record DS pubblicato dal registrar (automatico se sono lo stesso fornitore, altrimenti copiato a mano). Protegge dalle risposte DNS falsificate, non dal furto dell'account del registrar.
- Verifica: `dig +short DS example.com` restituisce il DS e `delv example.com SOA` dice "fully validated"; dnsviz.net mostra la catena.
- Un DS sbagliato rende il dominio irraggiungibile per i resolver che validano. Prima di cambiare servizio DNS: togliere il DS, aspettare il suo TTL (lo mostra `dig DS example.com`), migrare, riattivare.

### 3. CAA: chi può emettere certificati
- Le CA pubbliche devono rifiutare un certificato se il CAA del dominio non le elenca. Elencare solo le CA usate davvero da ogni servizio con un nome sul dominio: hosting, dominio personalizzato di Supabase, CDN, dominio di tracciamento del fornitore email. Leggere la pagina sui domini personalizzati di ciascuno: una CA mancante blocca il rinnovo.
- Il CAA del dominio principale vale anche per i sottodomini, salvo quelli con un CAA proprio o un CNAME verso un nome che ne ha uno. Senza certificati wildcard: `issuewild ";"`. Record nel blocco del punto 6.

### 4. Niente record pendenti, cautela con i wildcard
- Presa del sottodominio: un CNAME verso un servizio cancellato (app dell'hosting, bucket, sito di anteprima, help desk, landing page) può essere rivendicato da chiunque presso quel fornitore, che gli emette anche il certificato. Stesso rischio per A verso IP cloud rilasciati, NS verso zone cancellate, MX verso un fornitore lasciato, `include:` SPF di un servizio abbandonato.
- Quando si dismette un servizio: **prima** si toglie il record DNS, poi si cancella il servizio. Ogni record ha scopo e responsabile annotati (meglio il DNS come codice, per esempio DNSControl o OctoDNS, con modifiche via PR); revisione ogni trimestre.
- Un sottodominio preso eredita la fiducia data al dominio: cookie con `Domain=example.com`, CSP o CORS con `*.example.com`, Redirect URLs di Supabase Auth con `https://*.example.com/**` (il token del link di accesso finisce all'attaccante). Ovunque nomi esatti.
- Niente record wildcard (`*.example.com`) senza motivo, mai un CNAME wildcard verso un fornitore condiviso: ogni nome diventa rivendicabile. Certificati per nome invece che wildcard.
- Prova (un bersaglio che risolve può essere comunque libero: aprirlo e cercare pagine tipo "nessun sito qui"):
```sh
while read -r h; do t=$(dig +short CNAME "$h"); [ -n "$t" ] && [ -z "$(dig +short "$t")" ] && echo "PENDENTE: $h -> $t"; done < sottodomini.txt
```

### 5. Email dell'app su un sottodominio dedicato
- Codici, conferme e avvisi partono da un sottodominio usato solo per questo (`send.example.com`), verificato presso il fornitore; le caselle delle persone restano sul dominio principale, le newsletter su un terzo nome (`news.example.com`). Le reputazioni restano separate (le segnalazioni di spam su una newsletter non bloccano i codici di accesso) e i record del fornitore toccano solo il suo sottodominio.
- Supabase Auth: il servizio email incluso serve solo per le prove (pochi messaggi, solo agli indirizzi del team). In produzione SMTP proprio in Authentication → Emails → SMTP Settings, mittente `accesso@send.example.com` con il nome dell'app. La password SMTP è un segreto: solo nella dashboard, ruotata se esposta.
- Limiti di frequenza su iscrizioni, reset e link di accesso, più captcha (supabase-sicuro): senza, qualcuno usa il vostro modulo per riempire di email la casella di una vittima e brucia la vostra reputazione.

### 6. SPF, DKIM e DMARC
```
example.com.                      CAA   0 issue "letsencrypt.org"
example.com.                      CAA   0 issue "pki.goog"            ; solo se un servizio usa Google Trust Services
example.com.                      CAA   0 issuewild ";"
example.com.                      MX    10 mx.mailbox.provider.example.
example.com.                      TXT   "v=spf1 include:_spf.mailbox.provider.example -all"
send.example.com.                 MX    10 bounces.provider.example.  ; se il fornitore lo chiede per i rimbalzi
send.example.com.                 TXT   "v=spf1 include:_spf.provider.example -all"
sel1._domainkey.send.example.com. CNAME sel1.dkim.provider.example.
_dmarc.example.com.               TXT   "v=DMARC1; p=none; sp=none; rua=mailto:dmarc@example.com"
```
- SPF: un solo record `v=spf1` per nome (due sono un errore) e al massimo 10 ricerche DNS (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`). `~all` mentre si configura, `-all` quando l'elenco è completo; con DMARC a `reject` la differenza pratica è piccola. Togliere gli `include` dei servizi lasciati.
- DKIM: i record (spesso CNAME, così il fornitore ruota le chiavi) li dà il fornitore; chiavi da 2048 bit dove si sceglie. Togliere i selettori dei fornitori lasciati.
- DMARC passa se SPF o DKIM passano **e** sono allineati al dominio del `From`: in modo rilassato (default) basta lo stesso dominio registrato (`send.example.com` va con `example.com`), in modo stretto (`adkim=s; aspf=s`) serve lo stesso nome esatto. Conta soprattutto DKIM: SPF si rompe con gli inoltri.
- Percorso: `p=none` con `rua`, report letti per 2-4 settimane finché ogni fonte legittima passa (caselle, email dell'app, newsletter, fatture, help desk); poi `p=quarantine`, poi `p=reject`, con `sp` uguale. Se `rua` punta a un altro dominio, quello deve pubblicare `example.com._report._dmarc.<altro-dominio> TXT "v=DMARC1"`.
- Domini che non inviano (varianti, domini parcheggiati): `MX 0 .`, `TXT "v=spf1 -all"`, `_dmarc TXT "v=DMARC1; p=reject"`.
- Gmail e Yahoo dal 2024, Outlook.com dal 2025, chiedono a chi invia molto SPF, DKIM e DMARC allineato: senza, anche i codici di accesso finiscono nello spam o vengono rifiutati.

### 7. Contenuto delle email transazionali
- Nessun dato delicato, neanche nell'oggetto (si vede sulla schermata bloccata): niente testo delle chat, posizioni, indirizzi di amici, dati del profilo come orientamento, religione o politica. "Hai un nuovo messaggio" e un link all'app. L'email resta per anni presso più fornitori, viene inoltrata e letta su dispositivi condivisi. Anche l'avviso SOS ai contatti scelti dalla persona dice solo chi ha bisogno di aiuto e porta a una pagina autenticata e a scadenza con la posizione: mai coordinate o indirizzi nel testo o nell'oggetto (privacy-posizione §7).
- Nei link solo token opachi e monouso, mai email, id o altri dati personali nell'URL (finiscono in log e cronologie). Mai password nelle email.
- Codici e link brevi: 10-15 minuti, monouso, annullati dall'uso e dalla richiesta di uno nuovo (autenticazione-sicura). In Supabase: scadenza dell'OTP email a 600 secondi nelle impostazioni del provider Email.
- Gli scanner di sicurezza aziendali e alcuni client aprono i link per controllarli e consumano quelli monouso: la persona trova "link scaduto", o lo scanner conferma al posto suo. Preferire un codice da scrivere nell'app, oppure un link a una pagina di conferma sul vostro dominio dove l'azione parte solo al clic; mai cambiare stato con un semplice GET. Modello Supabase (Authentication → Emails → Templates):
```html
<p>Il tuo codice: <strong>{{ .Token }}</strong>. Scrivilo nell'app, scade tra 10 minuti. Nessuno del team te lo chiederà.</p>
<p>Oppure apri <a href="{{ .SiteURL }}/auth/conferma?token_hash={{ .TokenHash }}&type=email">la pagina di conferma</a>.</p>
```
```js
// /auth/conferma: niente al caricamento, gli scanner non cliccano
bottone.onclick = () => supabase.auth.verifyOtp({ token_hash: q.get('token_hash'), type: q.get('type') });
```
- Tracciamento di clic e aperture spento nelle email dell'account: riscrive i link verso il dominio del fornitore (il token passa da un terzo e il link non mostra più il vostro dominio) e il pixel rivela quando e da quale IP si legge.

### 8. Proteggere gli utenti dal phishing a vostro nome
- Mittente sempre uguale per tipo (nome e indirizzo); link solo verso il vostro dominio in `https`, niente accorciatori né domini di terzi. Una pagina del sito dice da quali indirizzi scrivete e che non chiedete mai via email password, codici, documenti o pagamenti; le email lo ripetono.
- Codice più link: chi è abituato a scrivere il codice nell'app non deve cliccare. Ciò che conta compare anche nell'app, così davanti a un'email dubbia la persona apre l'app da sé. Avvisi su accesso nuovo e cambi di email o password: autenticazione-sicura.
- Domini simili: registrare le varianti principali (altri TLD, refusi evidenti) e parcheggiarle senza email (punto 6). Siti di phishing: segnalarli all'abuse del registrar e dell'hosting e a Google Safe Browsing. Un `/.well-known/security.txt` (RFC 9116, con `Contact:` ed `Expires:`) dice dove mandare le segnalazioni.
- BIMI (logo accanto al mittente), facoltativo: richiede DMARC a `quarantine` o `reject`; Gmail mostra il logo solo con un certificato del marchio (VMC o CMC), a pagamento. Record: `default._bimi.example.com TXT "v=BIMI1; l=https://example.com/bimi.svg; a=https://example.com/bimi.pem"`.

### 9. Caselle di posta
- 2FA con app o passkey su ogni casella, prima di tutto su quelle che ricevono i reset delle console (Supabase, hosting, GitHub, registrar): sono la chiave di tutto. Spenti gli accessi con sola password (IMAP, POP e SMTP con autenticazione base, password per app inutilizzate).
- Ogni mese e dopo ogni allarme, controllare inoltri, filtri (soprattutto quelli che cancellano o archiviano "sicurezza", "password", "accesso"), deleghe e app collegate: chi prende una casella aggiunge un inoltro e nasconde gli avvisi. Nella console di amministrazione bloccare l'inoltro automatico verso indirizzi esterni.
- Indirizzi di ruolo (`security@`, `dmarc@`, `abuse@`, `postmaster@`) come gruppi con almeno due persone, non legati a un solo account.
- Facoltativo, per la posta in arrivo: MTA-STS (`_mta-sts.example.com TXT "v=STSv1; id=…"` più la policy su `https://mta-sts.example.com/.well-known/mta-sts.txt`) e TLS-RPT (`_smtp._tls.example.com TXT "v=TLSRPTv1; rua=mailto:…"`) impongono e controllano TLS tra i server.

### 10. Monitoraggio
- Report DMARC aggregati (`rua`, XML giornalieri): leggerli ogni settimana con un parser o un servizio, cercando fonti sconosciute che usano il vostro dominio e fallimenti delle vostre. I report forensi (`ruf`) contengono parti dei messaggi, cioè dati personali: non attivarli senza motivo.
- Certificate Transparency: ogni certificato emesso è pubblico. `https://crt.sh/?q=%25.example.com` (anche `&output=json`) o avvisi automatici (per esempio Cert Spotter): sottodomini sconosciuti, CA fuori dal CAA, il vostro marchio in domini altrui.
- Scadenze: oltre al rinnovo automatico, promemoria a 60 e 14 giorni dalla scadenza del dominio; un monitor esterno avvisa se il certificato scade entro 14 giorni (vuol dire che il rinnovo automatico è fallito, spesso per CAA o DNS).
- Differenze DNS: ogni settimana in CI, confronto con l'elenco versionato:
```sh
for n in example.com www.example.com send.example.com _dmarc.example.com; do for t in A AAAA CNAME MX TXT CAA NS; do
  dig +short "$n" "$t" | sed "s|^|$n $t |"; done; done | sort > dns-oggi.txt && diff dns-atteso.txt dns-oggi.txt
```

## Checklist
```sh
whois example.com | grep -iE 'status|expir'      # clientTransferProhibited, scadenza lontana
dig +short DS example.com; delv example.com SOA   # DNSSEC: DS presente, "fully validated"
dig +short CAA example.com                        # solo le CA usate, issuewild ";"
dig +short TXT send.example.com                   # un solo v=spf1
dig +short TXT sel1._domainkey.send.example.com   # chiave DKIM (selettore del fornitore)
dig +short TXT _dmarc.example.com                 # p=quarantine o reject, rua
```
Poi: un'email di prova a un indirizzo Gmail, "Mostra originale": SPF, DKIM e DMARC `PASS`; test email e sito di internet.nl senza errori gravi; nessun record pendente (punto 4); 2FA e inoltri delle caselle controllati; nessun dato delicato nei modelli delle email.

## Limiti da comunicare
- SPF, DKIM e DMARC fermano chi usa esattamente il vostro dominio, non i domini simili né i nomi visualizzati falsi ("Supporto App <x@gmail.com>"): servono anche avvisi chiari agli utenti e il monitoraggio.
- DNSSEC non protegge dal furto dell'account del registrar; il CAA non ferma una CA che lo ignora né un sottodominio preso presso un fornitore la cui CA è ammessa. Per questo contano 2FA, ordine di dismissione e Certificate Transparency.
- L'email non è un canale riservato: ciò che è delicato resta nell'app.
- Il monitoraggio trova i problemi dopo: serve qualcuno che legga report e avvisi.

---

# Domain and Email Security (English)

Whoever controls the domain controls the site, users' sign-in emails and the password resets of every console. App emails (codes, confirmations, notices) are also the first thing scammers imitate. This skill covers the registrar, DNS, certificates, email authentication and content, mailboxes and monitoring. Related: account-fornitori (console accounts), hardening-siti (HTTPS and headers), autenticazione-sicura (codes and verification at sign-in), risposta-incidenti (hijacked domain or spoofed email in progress). In the examples `example.com` is your domain and `provider.example` a provider: use the values your providers give you.

## Mandatory rules

### 1. Registrar and DNS accounts
- 2FA with an app or passkey, never SMS; two admins or offline recovery codes (account-fornitori). The same on the DNS service if it differs from the registrar; its API tokens scoped to the zone and, where enough, read-only.
- Transfer lock on (status `clientTransferProhibited`); for the main domain also registry lock, if the registrar offers it: every nameserver or contact change then needs out-of-band verification. Request the transfer code (auth code) only when needed.
- Auto-renew on, a valid card, renewal for several years; alerts on for nameserver, contact and record changes.
- Account and registrant email on **another domain** (an address with 2FA at another provider): if the domain expires or is hijacked, mail to `@example.com` stops arriving, or reaches the attacker, and so does the registrar's reset.
- Check: `whois example.com | grep -iE 'status|expir'`.

### 2. DNSSEC
- Turn it on if registrar and DNS support it: zone signing on the DNS service, DS record published at the registrar (automatic when they are the same provider, otherwise copied by hand). It protects against forged DNS answers, not against theft of the registrar account.
- Verify: `dig +short DS example.com` returns the DS and `delv example.com SOA` says "fully validated"; dnsviz.net shows the chain.
- A wrong DS makes the domain unreachable for validating resolvers. Before changing DNS service: remove the DS, wait for its TTL (`dig DS example.com` shows it), migrate, turn it back on.

### 3. CAA: who may issue certificates
- Public CAs must refuse a certificate when the domain's CAA does not list them. List only the CAs really used by each service with a name on the domain: hosting, Supabase custom domain, CDN, the email provider's tracking domain. Read each one's custom-domain page: a missing CA blocks renewal.
- The main domain's CAA also covers subdomains, except those with their own CAA or a CNAME to a name that has one. Without wildcard certificates: `issuewild ";"`. Records in the block of rule 6.

### 4. No dangling records, care with wildcards
- Subdomain takeover: a CNAME to a deleted service (hosting app, bucket, preview site, help desk, landing page) can be claimed by anyone at that provider, which also issues them a certificate. Same risk for A records to released cloud IPs, NS to deleted zones, MX to a provider you left, SPF `include:` of an abandoned service.
- When retiring a service: **first** remove the DNS record, then delete the service. Every record has a noted purpose and owner (better: DNS as code, e.g. DNSControl or OctoDNS, with changes via PR); review quarterly.
- A taken subdomain inherits the trust given to the domain: cookies with `Domain=example.com`, CSP or CORS with `*.example.com`, Supabase Auth Redirect URLs with `https://*.example.com/**` (the sign-in link's token goes to the attacker). Exact names everywhere.
- No wildcard records (`*.example.com`) without a reason, never a wildcard CNAME to a shared provider: every name becomes claimable. Per-name certificates instead of wildcard ones.
- Test (a target that resolves can still be unclaimed: open it and look for "no site here" pages):
```sh
while read -r h; do t=$(dig +short CNAME "$h"); [ -n "$t" ] && [ -z "$(dig +short "$t")" ] && echo "DANGLING: $h -> $t"; done < subdomains.txt
```

### 5. App email on a dedicated subdomain
- Codes, confirmations and notices are sent from a subdomain used only for that (`send.example.com`), verified with the provider; people's mailboxes stay on the main domain, newsletters on a third name (`news.example.com`). Reputations stay separate (spam complaints about a newsletter do not block sign-in codes) and the provider's records touch only its subdomain.
- Supabase Auth: the built-in email service is for testing only (few messages, team addresses only). In production, custom SMTP in Authentication → Emails → SMTP Settings, sender `signin@send.example.com` with the app's name. The SMTP password is a secret: only in the dashboard, rotated if exposed.
- Rate limits on sign-ups, resets and sign-in links, plus a captcha (supabase-sicuro): without them, someone uses your form to flood a victim's inbox and burns your reputation.

### 6. SPF, DKIM and DMARC
```
example.com.                      CAA   0 issue "letsencrypt.org"
example.com.                      CAA   0 issue "pki.goog"            ; only if a service uses Google Trust Services
example.com.                      CAA   0 issuewild ";"
example.com.                      MX    10 mx.mailbox.provider.example.
example.com.                      TXT   "v=spf1 include:_spf.mailbox.provider.example -all"
send.example.com.                 MX    10 bounces.provider.example.  ; if the provider asks for it, for bounces
send.example.com.                 TXT   "v=spf1 include:_spf.provider.example -all"
sel1._domainkey.send.example.com. CNAME sel1.dkim.provider.example.
_dmarc.example.com.               TXT   "v=DMARC1; p=none; sp=none; rua=mailto:dmarc@example.com"
```
- SPF: a single `v=spf1` record per name (two are an error) and at most 10 DNS lookups (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`). `~all` while setting up, `-all` once the list is complete; with DMARC at `reject` the practical difference is small. Remove the `include` of services you left.
- DKIM: the provider gives the records (often CNAMEs, so the provider rotates the keys); 2048-bit keys where you can choose. Remove the selectors of providers you left.
- DMARC passes if SPF or DKIM passes **and** is aligned with the `From` domain: relaxed (the default) needs the same registered domain (`send.example.com` goes with `example.com`), strict (`adkim=s; aspf=s`) needs the exact same name. DKIM matters most: SPF breaks on forwarding.
- Path: `p=none` with `rua`, reports read for 2-4 weeks until every legitimate source passes (mailboxes, app email, newsletters, invoices, help desk); then `p=quarantine`, then `p=reject`, with the same `sp`. If `rua` points to another domain, that domain must publish `example.com._report._dmarc.<other-domain> TXT "v=DMARC1"`.
- Domains that never send (variants, parked domains): `MX 0 .`, `TXT "v=spf1 -all"`, `_dmarc TXT "v=DMARC1; p=reject"`.
- Gmail and Yahoo since 2024, Outlook.com since 2025, require bulk senders to have SPF, DKIM and aligned DMARC: without them, even sign-in codes land in spam or get rejected.

### 7. Transactional email content
- No sensitive data, not even in the subject (it shows on the lock screen): no chat text, locations, friends' addresses, profile data such as orientation, religion or politics. "You have a new message" and a link to the app. Email stays for years with several providers, gets forwarded and is read on shared devices. The SOS alert to the contacts the person chose, too, only says who needs help and links to an authenticated, expiring page with the location: never coordinates or addresses in the body or subject (privacy-posizione §7).
- Links carry only opaque one-time tokens, never emails, ids or other personal data in the URL (they end up in logs and histories). Never passwords in emails.
- Short-lived codes and links: 10-15 minutes, single use, voided by use and by requesting a new one (autenticazione-sicura). In Supabase: email OTP expiry at 600 seconds in the Email provider settings.
- Corporate security scanners and some clients open links to check them and consume one-time ones: the person gets "link expired", or the scanner confirms on their behalf. Prefer a code typed into the app, or a link to a confirmation page on your domain where the action starts only on click; never change state on a plain GET. Supabase template (Authentication → Emails → Templates):
```html
<p>Your code: <strong>{{ .Token }}</strong>. Type it into the app, it expires in 10 minutes. Nobody on our team will ask you for it.</p>
<p>Or open <a href="{{ .SiteURL }}/auth/confirm?token_hash={{ .TokenHash }}&type=email">the confirmation page</a>.</p>
```
```js
// /auth/confirm: nothing on load, scanners do not click
button.onclick = () => supabase.auth.verifyOtp({ token_hash: q.get('token_hash'), type: q.get('type') });
```
- Click and open tracking off in account emails: it rewrites links to the provider's domain (the token passes through a third party and the link no longer shows your domain) and the pixel reveals when and from which IP the email is read.

### 8. Protect users from phishing in your name
- Always the same sender per type (name and address); links only to your domain over `https`, no shorteners or third-party domains. A page on the site says which addresses you write from and that you never ask by email for passwords, codes, documents or payments; the emails repeat it.
- Code plus link: people used to typing the code into the app do not need to click. What matters also shows in the app, so faced with a doubtful email people open the app themselves. Alerts on new sign-ins and email or password changes: autenticazione-sicura.
- Lookalike domains: register the main variants (other TLDs, obvious typos) and park them without email (rule 6). Phishing sites: report them to the registrar's and host's abuse contacts and to Google Safe Browsing. A `/.well-known/security.txt` (RFC 9116, with `Contact:` and `Expires:`) says where to send reports.
- BIMI (logo next to the sender), optional: needs DMARC at `quarantine` or `reject`; Gmail shows the logo only with a mark certificate (VMC or CMC), which costs money. Record: `default._bimi.example.com TXT "v=BIMI1; l=https://example.com/bimi.svg; a=https://example.com/bimi.pem"`.

### 9. Mailboxes
- 2FA with an app or passkey on every mailbox, first of all those receiving console resets (Supabase, hosting, GitHub, registrar): they are the key to everything. Password-only access off (IMAP, POP and SMTP with basic auth, unused app passwords).
- Monthly and after any alarm, check forwarding, filters (especially those deleting or archiving "security", "password", "sign-in"), delegates and connected apps: whoever takes a mailbox adds a forward and hides the alerts. In the admin console, block automatic forwarding to external addresses.
- Role addresses (`security@`, `dmarc@`, `abuse@`, `postmaster@`) as groups with at least two people, not tied to a single account.
- Optional, for incoming mail: MTA-STS (`_mta-sts.example.com TXT "v=STSv1; id=…"` plus the policy at `https://mta-sts.example.com/.well-known/mta-sts.txt`) and TLS-RPT (`_smtp._tls.example.com TXT "v=TLSRPTv1; rua=mailto:…"`) enforce and report TLS between servers.

### 10. Monitoring
- DMARC aggregate reports (`rua`, daily XML): read them weekly with a parser or a service, looking for unknown sources using your domain and failures of your own. Forensic reports (`ruf`) contain parts of messages, that is personal data: do not turn them on without a reason.
- Certificate Transparency: every issued certificate is public. `https://crt.sh/?q=%25.example.com` (also `&output=json`) or automatic alerts (e.g. Cert Spotter): unknown subdomains, CAs outside the CAA, your brand in other people's domains.
- Expiry: on top of auto-renew, reminders 60 and 14 days before the domain expires; an external monitor alerts if the certificate expires within 14 days (it means auto-renewal failed, often because of CAA or DNS).
- DNS differences: weekly in CI, compared with the versioned list:
```sh
for n in example.com www.example.com send.example.com _dmarc.example.com; do for t in A AAAA CNAME MX TXT CAA NS; do
  dig +short "$n" "$t" | sed "s|^|$n $t |"; done; done | sort > dns-today.txt && diff dns-expected.txt dns-today.txt
```

## Checklist
```sh
whois example.com | grep -iE 'status|expir'      # clientTransferProhibited, expiry far away
dig +short DS example.com; delv example.com SOA   # DNSSEC: DS present, "fully validated"
dig +short CAA example.com                        # only the CAs in use, issuewild ";"
dig +short TXT send.example.com                   # a single v=spf1
dig +short TXT sel1._domainkey.send.example.com   # DKIM key (the provider's selector)
dig +short TXT _dmarc.example.com                 # p=quarantine or reject, rua
```
Then: a test email to a Gmail address, "Show original": SPF, DKIM and DMARC `PASS`; internet.nl email and website tests without serious errors; no dangling records (rule 4); mailbox 2FA and forwarding checked; no sensitive data in email templates.

## Limits to communicate
- SPF, DKIM and DMARC stop whoever uses exactly your domain, not lookalike domains or fake display names ("App Support <x@gmail.com>"): clear notices to users and monitoring are needed too.
- DNSSEC does not protect against theft of the registrar account; CAA does not stop a CA that ignores it, nor a subdomain taken at a provider whose CA is allowed. That is why 2FA, the retirement order and Certificate Transparency matter.
- Email is not a confidential channel: what is sensitive stays in the app.
- Monitoring finds problems afterwards: someone has to read the reports and alerts.
