---
name: account-fornitori
description: Sicurezza degli account del team presso i fornitori e dei segreti - inventario degli account, 2FA o passkey ovunque, permessi minimi, GitHub protetto, gestione e rotazione dei segreti, catena CI/CD, uscita di un collaboratore, assistenti AI. Trigger - "2FA", "account", "GitHub", "segreti", "API key", "token", "accessi del team", "offboarding". EN - Security of the team's provider accounts and secrets - account inventory, 2FA or passkeys everywhere, least privilege, protected GitHub, secret management and rotation, CI/CD supply chain, offboarding, AI assistants. Triggers - "2FA", "accounts", "GitHub", "secrets", "API key", "tokens", "team access", "offboarding".
---

# Account dei fornitori e segreti · Provider Accounts and Secrets

> 🇮🇹 Versione italiana qui sotto · 🇬🇧 [English version below](#provider-accounts-and-secrets-english)

Un'app statica con Supabase non ha un server proprio da difendere: il suo server sono le console dei fornitori. Chi entra nell'account GitHub cambia il codice che va online, chi entra nell'hosting pubblica il JavaScript che vuole, chi entra in Supabase legge posizioni, chat e profili scavalcando la RLS, chi entra nel registrar o nell'email del dominio sposta il sito e reimposta tutte le altre password. Questa skill protegge gli account del team e i segreti. Altrove: 2FA degli utenti dell'app in autenticazione-sicura, workflow di scansione in sicurezza-github, segreti nel bundle in frontend-spa, DNS ed email del dominio in email-dominio, chiave esposta in risposta-incidenti.

## Regole obbligatorie

### 1. Inventario di ogni account
- Una riga per ogni account presso un fornitore: servizio, scopo, organizzazione o personale, proprietari, chi altro ha accesso e con quale ruolo, 2FA di ognuno, email di recupero, fatturazione (carta, scadenza, rinnovo), chiavi e token emessi con la data dell'ultima rotazione.
- Contare tutto: GitHub, Supabase, hosting, registrar e DNS, email del dominio, pagamenti, Apple e Google per gli store, mappe e geocoding, invio email, analytics, monitoraggio errori, npm, strumenti di AI, password manager.
- L'inventario contiene nomi e ruoli, mai password o chiavi. Tenerlo in una repo privata o nel password manager, con una copia offline (serve al runbook di risposta-incidenti).
```markdown
| Servizio | Scopo | Org/personale | Proprietari | Altri (ruolo) | 2FA | Recupero | Fatturazione | Chiavi (rotazione) |
|---|---|---|---|---|---|---|---|---|
| Supabase | DB, Auth, Storage | org "team" | Anna, Luca | Marco (Developer) | passkey x3 | admin@dominio | carta 09/27 | secret "edge" (2026-07) |
```

### 2. 2FA ovunque, codici di recupero offline
- 2FA su ogni account dell'inventario: passkey o chiave di sicurezza dove ci sono, altrimenti app di autenticazione (TOTP). SMS solo se è l'unica scelta: il numero si ruba con lo scambio della SIM.
- Dove il fornitore lo permette, imporre la 2FA a tutti i membri (GitHub: Organization settings → Authentication security → Require two-factor authentication).
- Per prima la casella email che riceve i reset: chi la controlla reimposta ogni altro account. 2FA forte e dominio con rinnovo automatico (email-dominio).
- Codici di recupero scaricati all'attivazione, stampati o in una cassaforte separata del password manager, mai nella stessa casella email né in una nota del telefono. Almeno due fattori per persona (due passkey, o passkey più app).
- Password uniche e generate, in un password manager di team con 2FA. Le credenziali condivise passano solo da lì, mai in chat.

### 3. Proprietari e privilegi minimi
- Account di organizzazione, non personali: repo in un'organizzazione GitHub, progetti in un'organizzazione Supabase, team sull'hosting, registrar e store intestati all'azienda (Apple come organizzazione chiede il numero D-U-N-S). Se sparisce l'unico account personale, sparisce il progetto.
- Registrazione con un indirizzo di ruolo sul proprio dominio (`admin@`, `security@`) che arriva ad almeno due persone, non la casella privata di uno.
- Almeno due proprietari per gli account critici (GitHub, Supabase, hosting, registrar, email, pagamenti, store). Dove il fornitore ammette un solo proprietario (Account Holder di Apple, proprietario dell'account Google Play), dare a una seconda persona il ruolo amministrativo più alto disponibile e scrivere la procedura di subentro.
- Tutti gli altri con il ruolo minimo: GitHub Read o Write, non Admin; Supabase Developer (o Read-only dove il piano lo offre), non Owner; sull'hosting membro, non proprietario. Collaboratori esterni solo sulle repo e sui progetti che toccano, con una data di fine.
- SSO (Google Workspace, Microsoft Entra ID) se il piano lo offre: l'accesso si toglie in un solo posto.

### 4. GitHub
- **Regole sul branch principale** (Settings → Rules → Rulesets, o Branch protection): pull request obbligatoria, almeno 1 approvazione annullata dai nuovi commit, controlli della CI obbligatori, niente force push né cancellazione, lista di bypass vuota. Da soli non ci si approva: tenere PR e controlli obbligatori, aggiungere le revisioni quando il team cresce.
- `CODEOWNERS` sui file che contano di più, con "Require review from Code Owners":
```
/supabase/migrations/  @org/backend
/.github/              @org/admin
/render.yaml           @org/admin
```
- **Secret scanning e push protection** attivi: gratis sulle repo pubbliche; sulle private servono le funzioni a pagamento (GitHub Secret Protection), altrimenti il workflow Gitleaks di sicurezza-github. **Dependabot alerts e security updates** attivi.
- **Actions** (Settings → Actions → General): solo azioni di GitHub, dei creatori verificati e di un elenco scelto; permessi del `GITHUB_TOKEN` in sola lettura per default; "Allow GitHub Actions to create and approve pull requests" spento; approvazione richiesta per i workflow lanciati da fork.
- **Deploy key** in sola lettura ("Allow write access" spento), una per servizio. App GitHub dell'hosting installate su "Only select repositories", non su tutte.
- **Token**: niente token classici; token a grana fine su una sola repo, con i soli permessi necessari e scadenza di 90 giorni o meno. Nell'organizzazione: token classici bloccati, token a grana fine con approvazione. Per le automazioni meglio una GitHub App o OIDC di un token personale.
- Chiavi SSH personali: togliere in Settings → SSH and GPG keys quelle di computer non più usati.

### 5. Dove stanno i segreti
- Segreti di runtime nelle variabili del fornitore: Environment su Render, Environment Variables su Vercel e Netlify, segreti delle Edge Functions (`supabase secrets set --env-file supabase/.env.local`, file ignorato da Git), segreti della CI nell'environment `production` di GitHub. Le persone li consultano solo nel password manager.
- In `render.yaml` i segreti si dichiarano con `sync: false`: il valore si inserisce nella dashboard e non finisce nel file. Su un sito statico le variabili dell'hosting servono solo al build e vanno nel bundle se usate dal codice: lì solo valori pubblici.
- Mai nella repo (neanche in un commit poi cancellato), in issue, PR, chat, email, ticket di supporto, schermate, prompt di AI. Nella repo solo i nomi:
```bash
# .env.example: names only, values live at the provider and in the password manager
VITE_SUPABASE_URL=
VITE_SUPABASE_PUBLISHABLE_KEY=
```
- `.gitignore` con `.env*` (tranne `!.env.example`) prima del primo commit; hook pre-commit con Gitleaks sui computer del team. Anche gli URL dei deploy hook dell'hosting sono segreti: chi li ha avvia un deploy.

### 6. Chiavi pubblicabili e segrete, una per ambiente
| Pubblica (browser) | Segreta (solo server, Edge Functions, CI) |
|---|---|
| Supabase `sb_publishable_…` (vecchia `anon`) | Supabase `sb_secret_…` (vecchia `service_role`), password del database, token personali della CLI |
| Stripe `pk_live_…` | Stripe `sk_live_…`, chiavi limitate `rk_live_…`, segreto dei webhook `whsec_…` |
| chiave delle mappe limitata al dominio | chiavi di email, SMS e AI, client secret OAuth |
- Un'app statica non ha un posto sicuro nel browser: ogni chiave segreta va in una Edge Function (api-sicura).
- Chiavi diverse per sviluppo, anteprima e produzione: progetti Supabase separati (o branch), Stripe in modalità test fuori dalla produzione. Computer degli sviluppatori e anteprime delle PR non hanno le chiavi segrete di produzione.
- Una chiave per uso (una secret per le Edge Functions, una per lo script di backup) e chiavi limitate dove esistono (restricted key di Stripe, chiavi delle mappe con limite di dominio e quota): se ne revoca una senza fermare il resto.

### 7. Rotazione e segreto trapelato
- Rotazione senza interruzioni: creare la chiave nuova, metterla dove serve, verificare, poi revocare la vecchia. Le nuove chiavi di Supabase ammettono più chiavi secret attive insieme proprio per questo.
- Quando: subito se un segreto può essere stato visto (commit, chat, schermata, log, prompt) o se esce una persona che lo conosceva; a calendario (per esempio ogni 6-12 mesi) per le chiavi a lunga durata, con la data nell'inventario.
- Segreto trapelato: è compromesso anche se cancellato dopo un minuto. 1) Revocarlo dal fornitore. 2) Mettere il nuovo dove serve. 3) Cercare nei log del fornitore l'uso tra la fuga e la revoca. 4) Solo dopo pulire. Riscrivere la cronologia Git non basta: restano fork, clone e cache. Il resto in risposta-incidenti.

### 8. Catena CI/CD
- Azioni di terzi fissate al commit completo, con la versione in commento; Dependabot (`package-ecosystem: "github-actions"`) aggiorna anche questi riferimenti:
```yaml
permissions:
  contents: read            # default for every job; widen per job only when needed
jobs:
  build:
    steps:
      - uses: actions/checkout@<sha-di-40-caratteri>  # vX.Y.Z
```
- Leggere il codice di un'azione di terzi prima di adottarla: meno azioni, meno rischi.
- Mai `pull_request_target` o `workflow_run` che eseguono codice della PR con i segreti disponibili. Mai `${{ github.event.* }}` dentro `run:`: passarlo con `env:` e usarlo come variabile (`"$TITLE"`).
- Produzione in un environment GitHub (`environment: production`) con i suoi segreti, solo dal branch principale e, dove il piano lo permette, con revisori obbligatori. Sull'hosting deploy automatico solo dal branch principale; anteprime delle PR con variabili separate, senza segreti di produzione.
- Build riproducibile: lockfile, `npm ci`, runtime fissato (frontend-spa, aggiornamenti-runtime).

### 9. Assistenti e agenti di AI
- Decidere per iscritto cosa può toccare l'agente: la repo sì, la produzione no per default. Token propri dell'agente, separati da quelli delle persone, a grana fine, su una repo, con scadenza: le sue azioni si riconoscono e si revocano da sole.
- L'agente lavora su un branch e apre PR; le regole del punto 4 valgono anche per lui; nessun ruolo Admin. Rivedere le sue modifiche come quelle di uno sconosciuto, soprattutto migrazioni, policy, workflow e dipendenze nuove.
- Server MCP del database: progetto di sviluppo, sola lettura, un solo progetto (Supabase: `read_only=true&project_ref=<ref>`); mai la chiave secret né un token personale valido per tutta l'organizzazione.
- Mai segreti nei prompt né in file che l'agente può leggere; bloccarne la lettura, per esempio in Claude Code (`.claude/settings.json`):
```json
{ "permissions": { "deny": ["Read(./.env)", "Read(./.env.*)", "Read(./supabase/.env*)"] } }
```
- Le regole `Read` valgono solo per gli strumenti di lettura dei file, non per i comandi della shell (`cat .env`): attivare anche il sandbox di Claude Code o negare quei comandi, e soprattutto tenere i segreti di produzione fuori dalla cartella di lavoro.
- Ciò che l'agente legge (issue, pagine web, README di pacchetti, righe del database) può contenere istruzioni nascoste (prompt injection): niente approvazione automatica di comandi shell, rete o scritture quando ci sono segreti raggiungibili.
- Dati degli utenti (chat, posizioni, profili con dati dell'art. 9 GDPR) non si incollano negli strumenti di AI senza contratto (DPA) e base giuridica (privacy-posizione). Account di AI di organizzazione con 2FA, uso dei dati per l'addestramento verificato nelle impostazioni, limiti di spesa sulle chiavi API.

### 10. Uscita di una persona
Lo stesso giorno, con l'inventario in mano:
1. togliere l'accesso a ogni console, al password manager condiviso, alle chat del team e all'indirizzo di ruolo;
2. revocare token, chiavi SSH, deploy key e app OAuth che ha creato o autorizzato;
3. trasferire ciò che è intestato a lei (repo personali, dominio, account dello store, carta di fatturazione);
4. ruotare i segreti condivisi che poteva vedere: chiavi secret, password del database, segreti dei webhook, credenziali condivise;
5. controllare inoltri email e webhook verso indirizzi sconosciuti; aggiornare l'inventario.
Lo stesso, in piccolo, per un cambio di ruolo o un computer perso.

### 11. Revisione trimestrale degli accessi
Ogni tre mesi, con la data nell'inventario:
- membri e ruoli di ogni console confrontati con il team reale; chi è senza 2FA (su GitHub la pagina People dell'organizzazione filtra per 2FA);
- token, chiavi API, deploy key, app GitHub e OAuth, webhook, integrazioni: togliere ciò che nessuno sa spiegare;
- registri di audit dove esistono (GitHub, Supabase, hosting): accessi da luoghi insoliti, chiavi create, ruoli cambiati;
- fatturazione: carte in scadenza, rinnovo del dominio, avvisi di spesa (un consumo che sale può essere una chiave rubata).

## Checklist
Inventario completo e aggiornato; 2FA forte su tutti, codici offline; due proprietari, gli altri al minimo; regole sul branch senza bypass; secret scanning, push protection e Dependabot; Actions in sola lettura e fissate al SHA; token con scadenza; nessun segreto nella repo o nel bundle; chiavi separate per ambiente; agenti con token propri e senza produzione; data dell'ultima revisione negli ultimi tre mesi.

## Limiti da comunicare
2FA e ruoli riducono il furto degli account, non lo azzerano: un computer infetto o una sessione rubata scavalcano la 2FA, quindi servono anche dispositivi aggiornati e sessioni chiuse quando non servono. Le regole valgono solo se nessuno ha il bypass. Revocare una chiave non cancella ciò che è già stato copiato con essa. Voci dei menu e funzioni dei piani cambiano: verificarle sul piano in uso.

---

# Provider Accounts and Secrets (English)

A static app on Supabase has no server of its own to defend: its server is the providers' consoles. Whoever gets into the GitHub account changes the code that ships, whoever gets into the hosting serves any JavaScript they like, whoever gets into Supabase reads locations, chats and profiles bypassing RLS, whoever gets into the registrar or the domain's email moves the site and resets every other password. This skill protects the team's accounts and secrets. Elsewhere: 2FA for the app's users in autenticazione-sicura, scanning workflows in sicurezza-github, secrets in the bundle in frontend-spa, the domain's DNS and email in email-dominio, a leaked key in risposta-incidenti.

## Mandatory rules

### 1. Inventory of every account
- One row per account at a provider: service, purpose, organisation or personal, owners, who else has access and with which role, everyone's 2FA, recovery email, billing (card, expiry, renewal), keys and tokens issued with the date of the last rotation.
- Count everything: GitHub, Supabase, hosting, registrar and DNS, domain email, payments, Apple and Google for the stores, maps and geocoding, email sending, analytics, error monitoring, npm, AI tools, password manager.
- The inventory holds names and roles, never passwords or keys. Keep it in a private repo or the password manager, with an offline copy (the risposta-incidenti runbook needs it).
```markdown
| Service | Purpose | Org/personal | Owners | Others (role) | 2FA | Recovery | Billing | Keys (rotation) |
|---|---|---|---|---|---|---|---|---|
| Supabase | DB, Auth, Storage | org "team" | Anna, Luca | Marco (Developer) | passkey x3 | admin@domain | card 09/27 | secret "edge" (2026-07) |
```

### 2. 2FA everywhere, recovery codes offline
- 2FA on every account in the inventory: a passkey or security key where available, otherwise an authenticator app (TOTP). SMS only when it is the only option: the number can be stolen with a SIM swap.
- Where the provider allows it, require 2FA for every member (GitHub: Organization settings → Authentication security → Require two-factor authentication).
- Start with the mailbox that receives resets: whoever controls it resets every other account. Strong 2FA and a domain on auto-renew (email-dominio).
- Recovery codes downloaded at setup, printed or in a separate password manager vault, never in the same mailbox or a phone note. At least two factors per person (two passkeys, or a passkey plus an app).
- Unique generated passwords, in a team password manager with 2FA. Shared credentials go through it only, never through chat.

### 3. Owners and least privilege
- Organisation accounts, not personal ones: repos in a GitHub organisation, projects in a Supabase organisation, a team on the hosting, registrar and stores in the company's name (Apple as an organisation asks for a D-U-N-S number). If the only personal account disappears, the project disappears.
- Sign up with a role address on your own domain (`admin@`, `security@`) that reaches at least two people, not one person's private mailbox.
- At least two owners for critical accounts (GitHub, Supabase, hosting, registrar, email, payments, stores). Where the provider allows only one owner (Apple's Account Holder, the Google Play account owner), give a second person the highest admin role available and write down the takeover procedure.
- Everyone else with the minimum role: GitHub Read or Write, not Admin; Supabase Developer (or Read-only where the plan offers it), not Owner; a member on the hosting, not an owner. External collaborators only on the repos and projects they touch, with an end date.
- SSO (Google Workspace, Microsoft Entra ID) if the plan offers it: access is removed in one place.

### 4. GitHub
- **Rules on the main branch** (Settings → Rules → Rulesets, or Branch protection): pull request required, at least 1 approval dismissed by new commits, required CI checks, no force push or deletion, empty bypass list. You cannot approve your own PR: when alone, keep PRs and checks required, add reviews as the team grows.
- `CODEOWNERS` on the files that matter most, with "Require review from Code Owners":
```
/supabase/migrations/  @org/backend
/.github/              @org/admin
/render.yaml           @org/admin
```
- **Secret scanning and push protection** on: free on public repos; private ones need the paid features (GitHub Secret Protection), otherwise the Gitleaks workflow from sicurezza-github. **Dependabot alerts and security updates** on.
- **Actions** (Settings → Actions → General): only actions by GitHub, by verified creators and from a chosen list; `GITHUB_TOKEN` read-only by default; "Allow GitHub Actions to create and approve pull requests" off; approval required for workflows triggered from forks.
- **Deploy keys** read-only ("Allow write access" off), one per service. The hosting's GitHub App installed on "Only select repositories", not on all of them.
- **Tokens**: no classic tokens; fine-grained tokens on a single repo, with only the permissions needed and an expiry of 90 days or less. In the organisation: classic tokens blocked, fine-grained tokens subject to approval. For automation, a GitHub App or OIDC beats a personal token.
- Personal SSH keys: remove those of computers no longer in use in Settings → SSH and GPG keys.

### 5. Where secrets live
- Runtime secrets in the provider's variables: Environment on Render, Environment Variables on Vercel and Netlify, Edge Function secrets (`supabase secrets set --env-file supabase/.env.local`, a file ignored by Git), CI secrets in GitHub's `production` environment. People look them up in the password manager only.
- In `render.yaml` declare secrets with `sync: false`: the value is typed into the dashboard and never lands in the file. On a static site the hosting's variables only feed the build and end up in the bundle if the code uses them: public values only there.
- Never in the repo (not even in a later-deleted commit), in issues, PRs, chats, emails, support tickets, screenshots, AI prompts. Only the names go in the repo:
```bash
# .env.example: names only, values live at the provider and in the password manager
VITE_SUPABASE_URL=
VITE_SUPABASE_PUBLISHABLE_KEY=
```
- `.gitignore` with `.env*` (except `!.env.example`) before the first commit; a Gitleaks pre-commit hook on the team's computers. The hosting's deploy hook URLs are secrets too: whoever holds one can trigger a deploy.

### 6. Publishable and secret keys, one per environment
| Public (browser) | Secret (server, Edge Functions, CI only) |
|---|---|
| Supabase `sb_publishable_…` (old `anon`) | Supabase `sb_secret_…` (old `service_role`), database password, CLI personal tokens |
| Stripe `pk_live_…` | Stripe `sk_live_…`, restricted keys `rk_live_…`, webhook secret `whsec_…` |
| map key restricted to your domain | email, SMS and AI keys, OAuth client secrets |
- A static app has no safe place in the browser: every secret key goes into an Edge Function (api-sicura).
- Different keys for development, preview and production: separate Supabase projects (or branches), Stripe test mode outside production. Developers' computers and PR previews do not hold production secret keys.
- One key per use (one secret for the Edge Functions, one for the backup script) and restricted keys where they exist (Stripe restricted keys, map keys with a domain and quota limit): you revoke one without stopping the rest.

### 7. Rotation and leaked secrets
- Rotation without downtime: create the new key, put it where it is needed, verify, then revoke the old one. Supabase's new keys allow several active secret keys at once for exactly this.
- When: at once if a secret may have been seen (commit, chat, screenshot, log, prompt) or a person who knew it leaves; on a schedule (e.g. every 6-12 months) for long-lived keys, with the date in the inventory.
- Leaked secret: it is compromised even if deleted a minute later. 1) Revoke it at the provider. 2) Put the new one where needed. 3) Search the provider's logs for use between the leak and the revocation. 4) Only then clean up. Rewriting Git history is not enough: forks, clones and caches remain. The rest is in risposta-incidenti.

### 8. CI/CD chain
- Third-party actions pinned to the full commit, with the version in a comment; Dependabot (`package-ecosystem: "github-actions"`) updates these references too:
```yaml
permissions:
  contents: read            # default for every job; widen per job only when needed
jobs:
  build:
    steps:
      - uses: actions/checkout@<40-character-sha>  # vX.Y.Z
```
- Read a third-party action's code before adopting it: fewer actions, less risk.
- Never `pull_request_target` or `workflow_run` running the PR's code with secrets available. Never `${{ github.event.* }}` inside `run:`: pass it through `env:` and use it as a variable (`"$TITLE"`).
- Production in a GitHub environment (`environment: production`) with its own secrets, only from the main branch and, where the plan allows, with required reviewers. On the hosting, auto-deploy only from the main branch; PR previews with separate variables, without production secrets.
- Reproducible build: lockfile, `npm ci`, pinned runtime (frontend-spa, aggiornamenti-runtime).

### 9. AI assistants and agents
- Decide in writing what the agent may touch: the repo yes, production no by default. The agent's own tokens, separate from people's, fine-grained, on one repo, with an expiry: its actions are recognisable and revocable on their own.
- The agent works on a branch and opens PRs; the rules in point 4 apply to it too; no Admin role. Review its changes like a stranger's, especially migrations, policies, workflows and new dependencies.
- Database MCP servers: development project, read-only, a single project (Supabase: `read_only=true&project_ref=<ref>`); never the secret key or a personal token valid for the whole organisation.
- Never secrets in prompts or in files the agent can read; block reading them, e.g. in Claude Code (`.claude/settings.json`):
```json
{ "permissions": { "deny": ["Read(./.env)", "Read(./.env.*)", "Read(./supabase/.env*)"] } }
```
- `Read` rules cover only the file tools, not shell commands (`cat .env`): also enable Claude Code's sandbox or deny those commands, and above all keep production secrets out of the working tree.
- What the agent reads (issues, web pages, package READMEs, database rows) can carry hidden instructions (prompt injection): no auto-approval of shell commands, network access or writes while secrets are within reach.
- Users' data (chats, locations, profiles with GDPR art. 9 data) is not pasted into AI tools without a contract (DPA) and a legal basis (privacy-posizione). Organisation AI accounts with 2FA, training use of data checked in the settings, spending limits on API keys.

### 10. When a person leaves
The same day, inventory in hand:
1. remove access to every console, the shared password manager, the team's chats and the role address;
2. revoke tokens, SSH keys, deploy keys and OAuth apps they created or authorised;
3. transfer whatever is in their name (personal repos, domain, store account, billing card);
4. rotate the shared secrets they could see: secret keys, database password, webhook secrets, shared credentials;
5. check email forwarding and webhooks to unknown addresses; update the inventory.
The same, on a smaller scale, for a role change or a lost computer.

### 11. Quarterly access review
Every three months, with the date in the inventory:
- members and roles of every console compared with the real team; who lacks 2FA (on GitHub the organisation's People page filters by 2FA);
- tokens, API keys, deploy keys, GitHub and OAuth apps, webhooks, integrations: remove whatever nobody can explain;
- audit logs where they exist (GitHub, Supabase, hosting): sign-ins from unusual places, keys created, roles changed;
- billing: expiring cards, domain renewal, spending alerts (rising usage can be a stolen key).

## Checklist
Complete, up-to-date inventory; strong 2FA for everyone, codes offline; two owners, everyone else minimal; branch rules with no bypass; secret scanning, push protection and Dependabot; Actions read-only and pinned to a SHA; tokens with an expiry; no secrets in the repo or the bundle; separate keys per environment; agents with their own tokens and no production; last review within three months.

## Limits to communicate
2FA and roles reduce account takeover, they do not eliminate it: an infected computer or a stolen session bypasses 2FA, so up-to-date devices and closing sessions when not needed matter too. The rules only hold if nobody has a bypass. Revoking a key does not erase what was already copied with it. Menu labels and plan features change: check them on the plan in use.
