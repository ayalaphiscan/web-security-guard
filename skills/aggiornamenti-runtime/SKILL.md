---
name: aggiornamenti-runtime
description: Tiene aggiornati i runtime e gli interpreti su cui gira un sito (PHP, Node.js, Python, immagini Docker, hosting) e reagisce agli avvisi di sicurezza urgenti. Le falle dell'interprete non si chiudono aggiornando l'applicazione. Trigger - "aggiorna PHP", "versione di Node", "falla critica", "CVE", "patch di sicurezza", "il mio hosting è aggiornato?", "PHP2Shell". EN - Keeps the runtimes and interpreters a site runs on (PHP, Node.js, Python, Docker images, hosting) patched and responds to urgent security advisories; interpreter flaws are not fixed by updating the application. Triggers - "update PHP", "Node version", "critical vulnerability", "CVE", "security patch", "is my hosting patched?", "PHP2Shell".
---

# Aggiornamenti runtime · Runtime patching

> 🇮🇹 Versione italiana qui sotto · 🇬🇧 [English version below](#runtime-patching-english)

Le difese dell'applicazione (validazione, middleware guardian, WAF applicativo) non servono se la falla è nell'interprete: l'attacco arriva prima del codice del sito. Esempio di ottobre 2026: **PHP2Shell** (CVE-2026-109618 e CVE-2026-109619) esegue codice su qualunque server PHP vulnerabile, e aggiornare WordPress, i temi o i plugin non serve. Lo stesso giorno Node.js ha corretto 10 falle, compresa un'esecuzione di codice nel decoder Brotli. Per questo la versione del runtime fa parte della sicurezza tanto quanto il codice.

## Regole obbligatorie

### 1. Sapere cosa gira dove
Per ogni progetto, scrivere (nel README o nella documentazione) l'inventario:
- **Runtime in produzione**: linguaggio e versione (PHP 8.x, Node 22.x, Python 3.x), dove gira (VPS, container, hosting condiviso, serverless).
- **Runtime solo di build**: per esempio Node per costruire un sito statico. Conta meno, ma va aggiornato anche lui, perché scarica pacchetti da internet.
- **Servizi gestiti** (database, auth, email, CDN): li aggiorna il fornitore. Si annota chi è e dove legge gli avvisi.
Con l'inventario, davanti a un avviso si capisce in pochi minuti se ci riguarda.

### 2. Versioni supportate e fissate
- Usare solo rami ancora supportati. Ottobre 2026:
  - PHP 8.2, 8.3, 8.4, 8.5 (8.1 e precedenti sono fuori supporto);
  - Node.js 22 e 24 LTS, oppure 26 (Node 20 è fuori supporto dal 30 aprile 2026);
  - Python 3.11 o più recente (3.10 è fuori supporto da ottobre 2026).
- Fissare la versione in un file del progetto, così build, CI e produzione usano la stessa:
  - Node: `.node-version` o `.nvmrc`; nella CI `actions/setup-node` con `node-version-file`;
  - PHP: `composer.json` (`"php": ">=8.3.36"`) e l'immagine Docker;
  - Docker: tag con la patch, per esempio `node:22.23.4-alpine` o `php:8.3.36-fpm`, mai `latest`. Ancora meglio, il digest `@sha256:…`.
- Dependabot con `package-ecosystem: "docker"` propone da solo le immagini nuove (skill sicurezza-github).

### 3. Quando esce un avviso urgente
1. Leggere l'avviso ufficiale (php.net, nodejs.org/en/blog/vulnerability, la pagina sicurezza del fornitore) e annotare le versioni corrette: valgono quelle dell'avviso, non quelle di esempio qui sotto. Esempio, 21 ottobre 2026:
   - PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35;
   - Node 26.12.1, 24.22.1, 22.23.4.
2. Confrontarle con l'inventario: cosa è esposto, dove.
3. Aggiornare in quest'ordine: esposto a internet (proxy, API, siti PHP), poi interno, poi build e CI.
4. **Container**: aggiornare il sistema operativo dell'host non basta. Bisogna cambiare il tag della base, ricostruire l'immagine (`docker build --pull`) e ridistribuirla.
5. **Hosting condiviso o gestito**: chiedere al supporto: "Il server è aggiornato con le patch del <data> per <CVE>? Quale versione di PHP/Node gira ora?". Se la versione è fuori supporto, migrare.
6. Verificare dopo l'aggiornamento: `php -v`, `node --version`, l'intestazione `X-Powered-By` (che va comunque nascosta), il log di build della piattaforma.
7. Se c'è stato sfruttamento prima della patch: ruotare segreti e chiavi, controllare file nuovi o modificati sul server e i log, e ripristinare da backup puliti (skill architettura-fortezza).

### 4. Routine
- Una volta al mese, e subito dopo un avviso critico, ricontrollare l'inventario.
- Nella CI far fallire la build se la versione del runtime è fuori supporto (per esempio un controllo su `.node-version`).

## Limiti da comunicare
L'aggiornamento chiude le falle note, non quelle sconosciute. Riduce il rischio solo insieme a: superficie minima (niente servizi esposti inutili), privilegi minimi, backup verificati e monitoraggio dei log.

---

# Runtime patching (English)

Application defenses (validation, the guardian middleware, an application WAF) do not help when the flaw is in the interpreter: the attack lands before the site's code runs. October 2026 example: **PHP2Shell** (CVE-2026-109618 and CVE-2026-109619) runs code on any vulnerable PHP server, and updating WordPress, themes or plugins does nothing. The same day Node.js fixed 10 flaws, including code execution in the Brotli decoder. So the runtime version is part of security as much as the code.

## Mandatory rules

### 1. Know what runs where
For every project, write down the inventory (README or docs):
- **Production runtimes**: language and version (PHP 8.x, Node 22.x, Python 3.x), where it runs (VPS, container, shared hosting, serverless).
- **Build-only runtimes**: e.g. Node to build a static site. It matters less, but it must be patched too, because it downloads packages from the internet.
- **Managed services** (database, auth, email, CDN): the provider patches them. Note who it is and where they publish advisories.
With the inventory, you can tell within minutes whether an advisory affects you.

### 2. Supported, pinned versions
- Only use branches that are still supported. October 2026:
  - PHP 8.2, 8.3, 8.4, 8.5 (8.1 and older are end-of-life);
  - Node.js 22 and 24 LTS, or 26 (Node 20 has been end-of-life since 30 April 2026);
  - Python 3.11 or newer (3.10 is end-of-life from October 2026).
- Pin the version in a project file, so build, CI and production use the same one:
  - Node: `.node-version` or `.nvmrc`; in CI, `actions/setup-node` with `node-version-file`;
  - PHP: `composer.json` (`"php": ">=8.3.36"`) and the Docker image;
  - Docker: a tag with the patch, e.g. `node:22.23.4-alpine` or `php:8.3.36-fpm`, never `latest`. Better still, the `@sha256:…` digest.
- Dependabot with `package-ecosystem: "docker"` proposes new images on its own (sicurezza-github skill).

### 3. When an urgent advisory lands
1. Read the official advisory (php.net, nodejs.org/en/blog/vulnerability, the provider's security page) and note the fixed versions: the advisory's numbers count, not the examples below. Example, 21 October 2026:
   - PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35;
   - Node 26.12.1, 24.22.1, 22.23.4.
2. Compare them with the inventory: what is exposed, and where.
3. Update in this order: internet-facing (proxies, APIs, PHP sites), then internal, then build and CI.
4. **Containers**: updating the host OS is not enough. Change the base tag, rebuild the image (`docker build --pull`) and redeploy it.
5. **Shared or managed hosting**: ask support: "Is the server patched with the <date> fixes for <CVE>? Which PHP/Node version runs now?". If the version is end-of-life, migrate.
6. Verify after updating: `php -v`, `node --version`, the `X-Powered-By` header (which should be hidden anyway), the platform's build log.
7. If the flaw was exploited before the patch: rotate secrets and keys, look for new or changed files on the server and in the logs, and restore from clean backups (architettura-fortezza skill).

### 4. Routine
- Re-check the inventory monthly, and right after any critical advisory.
- Make CI fail when the runtime version is end-of-life (e.g. a check on `.node-version`).

## Limitation to communicate
Patching closes known flaws, not unknown ones. It only reduces risk together with: minimal surface (no needless exposed services), least privilege, verified backups and log monitoring.
