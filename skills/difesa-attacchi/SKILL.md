---
name: difesa-attacchi
description: Aggiunge a un sito/app un agente di difesa che rileva e blocca richieste malevole (SQL injection, XSS, path traversal, brute force, bot) con rate limiting, blocklist IP e modalità lockdown che preserva i dati. Trigger - "blocca attacchi", "firewall", "WAF", "lockdown", "sotto attacco". EN - Adds a defense agent that detects and blocks malicious requests (SQL injection, XSS, path traversal, brute force, bots) with rate limiting, IP blocklist and a data-preserving lockdown mode. Triggers - "block attacks", "firewall", "WAF", "lockdown", "defend my site", "rate limiting", "under attack".
---

# Difesa Attacchi (agente guardian) · Attack Defense

> 🇮🇹 Versione italiana qui sotto · 🇬🇧 [English version below](#attack-defense-guardian-agent-english)

Quando l'utente vuole protezione attiva dagli attacchi, integrare nel progetto il middleware "guardian". Il codice pronto è in `references/guardian-express.js` (Node/Express); per altri stack (Flask/Django, PHP) adattare la stessa logica.

## Cosa fa il guardian
1. **Rilevamento pattern malevoli** su URL, query, body e header: SQL injection, XSS, path traversal, command injection, scanner noti.
2. **Rate limiting** per IP (generale + più severo su login/pagamenti).
3. **Blocklist automatica**: un IP che supera la soglia di richieste malevole viene bloccato temporaneamente, con escalation se recidivo.
4. **Modalità lockdown**: se gli eventi malevoli superano la soglia globale, il sito entra in stato di chiusura controllata — risponde 503 con pagina di manutenzione, blocca ogni scrittura, mantiene i dati intatti e (se configurato) esegue un backup e invia un alert.
5. **Logging strutturato** di ogni evento in `security-events.log` per analisi successiva.

## Come integrarlo (Express)
```js
const { guardian } = require('./security/guardian');
app.use(guardian({
  rateLimit: { windowMs: 60000, max: 120 },
  strictPaths: ['/login', '/api/auth', '/api/pay'],   // limite 10/min
  lockdown: { threshold: 50, windowMs: 300000, unlockAfterMs: 900000 },
  onAlert: async (evento) => { /* email/webhook all'amministratore */ },
  onLockdown: async () => { /* backup DB, notifica */ }
}));
```
Montarlo PRIMA delle route. Copiare `references/guardian-express.js` in `security/guardian.js` nel progetto e adattare le soglie.

## Regole di implementazione
- Il guardian è una difesa in profondità, NON sostituisce query parametrizzate, validazione e hardening (skill hardening-siti): applicare comunque quelle regole.
- Dietro proxy/CDN ricavare l'IP reale da `X-Forwarded-For` solo se il proxy è fidato (`app.set('trust proxy', 1)`).
- Il lockdown NON deve mai cancellare dati: solo bloccare l'accesso in scrittura e servire la pagina di manutenzione. Lo sblocco è automatico dopo il timeout o manuale (file flag `LOCKDOWN` rimovibile / variabile env).
- Escludere dai controlli i webhook di pagamento verificati con firma (altrimenti payload legittimi possono sembrare sospetti) — la sicurezza lì è la firma (skill privacy-pagamenti).
- Consigliare SEMPRE anche una protezione a livello di piattaforma (Cloudflare/WAF dell'hosting): il middleware difende l'applicazione, non assorbe DDoS volumetrici.

## Risposta agli incidenti
In caso di attacco rilevato suggerire all'utente: 1) esaminare `security-events.log`, 2) ruotare le chiavi/segreti se c'è sospetto di compromissione, 3) verificare integrità dati con il backup, 4) mantenere il lockdown finché la falla non è chiusa.

---

# Attack Defense (guardian agent) (English)

When the user wants active protection from attacks, integrate the "guardian" middleware into the project. Ready-made code is in `references/guardian-express.js` (Node/Express); for other stacks (Flask/Django, PHP) adapt the same logic.

## What guardian does
1. **Malicious pattern detection** on URL, query, body and headers: SQL injection, XSS, path traversal, command injection, known scanners.
2. **Rate limiting** per IP (general + stricter on login/payments).
3. **Automatic blocklist**: an IP exceeding the malicious-request threshold is temporarily blocked, with escalation for repeat offenders.
4. **Lockdown mode**: if malicious events exceed the global threshold, the site enters controlled shutdown — responds 503 with a maintenance page, blocks all writes, keeps data intact and (if configured) runs a backup and sends an alert.
5. **Structured logging** of every event to `security-events.log` for later analysis.

## How to integrate it (Express)
Use the same snippet as above; mount it BEFORE the routes. Copy `references/guardian-express.js` to `security/guardian.js` in the project and tune the thresholds.

## Implementation rules
- Guardian is defense in depth — it does NOT replace parameterized queries, validation and hardening (hardening-siti skill): apply those rules anyway.
- Behind a proxy/CDN derive the real IP from `X-Forwarded-For` only if the proxy is trusted (`app.set('trust proxy', 1)`).
- Lockdown must NEVER delete data: only block write access and serve the maintenance page. Unlock is automatic after the timeout or manual (removable `LOCKDOWN` flag file / env variable).
- Exclude signature-verified payment webhooks from the checks (legitimate payloads can look suspicious) — security there is the signature (privacy-pagamenti skill).
- ALWAYS also recommend platform-level protection (Cloudflare / hosting WAF): the middleware defends the application, it does not absorb volumetric DDoS.

## Incident response
When an attack is detected, advise the user to: 1) review `security-events.log`, 2) rotate keys/secrets if compromise is suspected, 3) verify data integrity against the backup, 4) keep the lockdown until the hole is fixed.
