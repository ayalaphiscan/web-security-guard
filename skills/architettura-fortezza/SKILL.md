---
name: architettura-fortezza
description: Progetta e installa un'infrastruttura di sicurezza a 4 livelli dove il cuore (dati e chiavi) è offline, lo scudo è invisibile agli scanner e il server reale è nascosto. Trigger - "fortezza", "scatola chiusa", "invisibile", "nascosto", "reverse proxy", "air gap", "cassaforte", "WireGuard". EN - Designs and installs a 4-layer security infrastructure where the core (data and keys) is offline and detached, the shield is invisible to scanners and the real server is hidden. Use for a self-hosted Cloudflare alternative, invisible reverse proxy, hidden server, WireGuard VPN, or unreachable offline backups. Triggers - "fortress", "hidden server", "invisible proxy", "air gap", "offline vault", "WireGuard".
---

# Architettura Fortezza (4 livelli) · Fortress Architecture

> 🇮🇹 Versione italiana qui sotto · 🇬🇧 [English version below](#fortress-architecture-4-layers-english)

Quando l'utente vuole un sistema "blindato" dove il cuore è staccato e lo scudo è
invisibile, proporre e installare questa architettura. I file template completi
(proxy guardian, Caddy, docker-compose, firewall, WireGuard, backup cifrati) sono
in `references/fortezza/` dentro questa skill; questa skill spiega come adattarli.

## Premessa onesta da dare SEMPRE all'utente
La porta web pubblica non può essere invisibile: se i visitatori la raggiungono,
la raggiunge anche chi attacca. Invisibili possono diventare invece SSH,
l'amministrazione, il server reale e la cassaforte. E i DDoS volumetrici enormi
restano gestibili solo con un CDN/WAF esterno (es. Cloudflare free) davanti allo
scudo. Non promettere "non attaccabile": promettere "superficie ridotta al minimo,
cuore irraggiungibile, dati sempre recuperabili".

## I quattro livelli

1. **Scudo invisibile** — unica macchina pubblica. Caddy (HTTPS + rimozione
   impronte) → proxy `guardian` (WAF, rate limit, blocklist silenziosa, lockdown,
   honeypot). Firewall stealth: solo 80/443 visibili, resto in DROP, niente ping.
2. **Server origine nascosto** — sito + DB, nessuna porta pubblica, accetta solo
   lo scudo via VPN. L'app ascolta sull'IP VPN, mai esposta dal provider.
3. **WireGuard** — rete privata cifrata tra scudo, origine e admin. Non risponde
   senza chiave valida → invisibile agli scanner. Solo gli `AllowedIPs` passano.
4. **Cassaforte offline** — air-gapped, custodisce la chiave privata. Backup
   cifrati con chiave pubblica (il server cifra ma non può decifrare). La
   cassaforte va a prendere i backup (sola andata); il server non la conosce.

## Principi di progettazione da rispettare
- **Minima superficie**: ogni livello espone solo ciò che serve al livello accanto.
- **Conoscenza parziale**: ogni macchina conosce solo il vicino, mai l'intera catena.
- **One-way verso il cuore**: nessun percorso che parta dal server e arrivi alla cassaforte.
- **Cifratura asimmetrica**: chi può essere compromesso (il server) ha solo la chiave pubblica.
- **Silenzio**: agli attaccanti non si risponde (stealth), per non dare impronte né feedback.
- **Difesa in profondità**: questa architettura si SOMMA alle altre skill del plugin
  (hardening-siti, difesa-attacchi, privacy-pagamenti, autenticazione-sicura), non le sostituisce.

## Installazione (ordine)
1. Cassaforte: generare le chiavi offline (`genera-chiavi.sh`).
2. WireGuard su scudo, origine, admin.
3. Origine: avviare app su IP VPN, poi `firewall-origine.sh`.
4. Scudo: configurare `ORIGIN_URL` e dominio, `docker compose up -d --build`, `firewall-stealth.sh`.
5. Backup: cron notturno di `backup-cifrato.sh` sull'origine; pull periodico dalla cassaforte.

## Verifica
Da macchina esterna `nmap -Pn IP_SCUDO`: solo 80/443. SSH/WireGuard invisibili.
Il server origine non deve rispondere. Provare un ripristino di backup sulla
cassaforte per confermare che la catena funziona.

---

# Fortress Architecture (4 layers) (English)

When the user wants an "armored" system where the core is detached and the shield
is invisible, propose and install this architecture. Complete template files
(guardian proxy, Caddy, docker-compose, firewall, WireGuard, encrypted backups)
are in `references/fortezza/` inside this skill; this skill explains how to adapt them.

## Honest disclaimer to ALWAYS give the user
The public web port cannot be invisible: if visitors can reach it, so can
attackers. What can become invisible are SSH, administration, the real server
and the vault. Massive volumetric DDoS can only be handled by an external
CDN/WAF (e.g. Cloudflare free) in front of the shield. Don't promise
"unhackable": promise "minimal attack surface, unreachable core, always
recoverable data".

## The four layers

1. **Invisible shield** — the only public machine. Caddy (HTTPS + fingerprint
   removal) → `guardian` proxy (WAF, rate limiting, silent blocklist, lockdown,
   honeypot). Stealth firewall: only 80/443 visible, everything else DROP, no ping.
2. **Hidden origin server** — site + DB, no public ports, accepts only the
   shield via VPN. The app listens on the VPN IP, never exposed by the provider.
3. **WireGuard** — encrypted private network between shield, origin and admin.
   Doesn't respond without a valid key → invisible to scanners. Only `AllowedIPs` pass.
4. **Offline vault** — air-gapped, holds the private key. Backups encrypted with
   the public key (the server encrypts but cannot decrypt). The vault pulls the
   backups (one-way); the server doesn't know it exists.

## Design principles to respect
- **Minimal surface**: each layer exposes only what the adjacent layer needs.
- **Partial knowledge**: each machine knows only its neighbor, never the whole chain.
- **One-way toward the core**: no path starting at the server can reach the vault.
- **Asymmetric encryption**: whatever can be compromised (the server) holds only the public key.
- **Silence**: attackers get no responses (stealth) — no fingerprints, no feedback.
- **Defense in depth**: this architecture ADDS to the other skills of the plugin
  (hardening-siti, difesa-attacchi, privacy-pagamenti, autenticazione-sicura), it does not replace them.

## Installation (order)
1. Vault: generate keys offline (`genera-chiavi.sh`).
2. WireGuard on shield, origin, admin.
3. Origin: start the app on the VPN IP, then `firewall-origine.sh`.
4. Shield: configure `ORIGIN_URL` and domain, `docker compose up -d --build`, `firewall-stealth.sh`.
5. Backups: nightly cron of `backup-cifrato.sh` on the origin; periodic pull from the vault.

## Verification
From an external machine `nmap -Pn SHIELD_IP`: only 80/443. SSH/WireGuard invisible.
The origin server must not respond. Test a backup restore on the vault to confirm
the chain works.
