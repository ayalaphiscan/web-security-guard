---
name: autenticazione-sicura
description: Implementa autenticazione sicura quando un sito/app richiede registrazione, login o account utente. Copre verifica email con codice, 2FA/TOTP, passkey, hashing password, sessioni e recupero account. Trigger - "login", "registrazione", "verifica email", "2FA", "passkey". EN - Implements secure authentication when a site/app needs sign-up, login or user accounts. Covers email verification codes, two-factor authentication (2FA/TOTP), passkeys and security keys, password hashing, sessions and account recovery. Triggers - "login", "sign up", "email verification", "2FA", "two-factor", "passkey", "user accounts".
---

# Autenticazione Sicura · Secure Authentication

> 🇮🇹 Versione italiana qui sotto · 🇬🇧 [English version below](#secure-authentication-english)

Quando un sito/app prevede account utente, implementare l'autenticazione secondo queste regole. Se l'utente non specifica i dettagli, proporre di default: password + verifica email con codice + 2FA opzionale.

## Password
- Hash con **Argon2id** (preferito) o bcrypt (cost ≥ 12). MAI MD5/SHA1/SHA256 semplice, mai password in chiaro.
- Lunghezza minima 8-12 caratteri; verificare contro liste di password compromesse se possibile.
- Rate limiting sul login: max ~5 tentativi per account/IP in 15 minuti, poi blocco temporaneo crescente. Risposta identica per "utente inesistente" e "password errata".

## Verifica email con codice (OTP)
- Codice numerico a 6 cifre generato con CSPRNG (`crypto.randomInt`, `secrets.randbelow`), MAI `Math.random()`.
- Validità 10 minuti, monouso, max 5 tentativi di inserimento, poi invalidare e rigenerare.
- Salvare nel DB solo l'hash del codice, con scadenza. Rate limiting sull'invio (max 1 ogni 60s, 5/ora per indirizzo).
- Stesso schema per: conferma registrazione, reset password, conferma di azioni sensibili (cambio email, cambio IBAN, cancellazione account).

## 2FA / doppio fattore
Offrire in ordine di preferenza:
1. **Passkey / chiavi di sicurezza (WebAuthn/FIDO2)** — resistenti al phishing. Librerie: `@simplewebauthn/server` (Node), `webauthn` (Python).
2. **TOTP** (Google Authenticator ecc.) — segreto generato server-side, mostrato via QR, verificato con finestra ±1 step. Librerie: `otplib`, `pyotp`.
3. **Codice via email** — minimo accettabile; SMS solo se richiesto esplicitamente.

Regole:
- Alla attivazione del 2FA generare **10 codici di recupero** monouso (mostrati una sola volta, salvati hashati).
- Richiedere il 2FA a ogni login da dispositivo nuovo e per azioni sensibili (step-up).
- Disattivazione 2FA solo con ri-autenticazione completa.

## Sessioni e token
- Vedi skill hardening-siti per i cookie. In più: invalidare tutte le sessioni al cambio password; lista "dispositivi connessi" con revoca.
- Se si usano JWT: scadenza breve (15 min) + refresh token revocabile salvato server-side; algoritmo fissato (no `alg: none`).

## Recupero account
- Reset password tramite link/codice monouso a scadenza, MAI domande di sicurezza.
- Notificare via email ogni evento sensibile: login da nuovo dispositivo, cambio password/email, attivazione/disattivazione 2FA.

## Cosa non fare mai
- Inviare password via email. Loggare password o codici OTP. Rivelare se un'email è registrata (enumerazione). Implementare crittografia "fatta in casa".

---

# Secure Authentication (English)

When a site/app has user accounts, implement authentication following these rules. If the user doesn't specify details, propose by default: password + email verification code + optional 2FA.

## Passwords
- Hash with **Argon2id** (preferred) or bcrypt (cost ≥ 12). NEVER plain MD5/SHA1/SHA256, never plaintext passwords.
- Minimum length 8-12 characters; check against breached-password lists when possible.
- Rate limiting on login: max ~5 attempts per account/IP in 15 minutes, then increasing temporary lockout. Identical response for "user not found" and "wrong password".

## Email verification codes (OTP)
- 6-digit numeric code generated with a CSPRNG (`crypto.randomInt`, `secrets.randbelow`), NEVER `Math.random()`.
- Valid 10 minutes, single-use, max 5 entry attempts, then invalidate and regenerate.
- Store only the code's hash in the DB, with expiry. Rate-limit sending (max 1 per 60s, 5/hour per address).
- Same scheme for: sign-up confirmation, password reset, confirmation of sensitive actions (email change, bank details change, account deletion).

## 2FA / two-factor
Offer in order of preference:
1. **Passkeys / security keys (WebAuthn/FIDO2)** — phishing-resistant. Libraries: `@simplewebauthn/server` (Node), `webauthn` (Python).
2. **TOTP** (Google Authenticator etc.) — secret generated server-side, shown via QR, verified with a ±1 step window. Libraries: `otplib`, `pyotp`.
3. **Email code** — acceptable minimum; SMS only if explicitly requested.

Rules:
- On 2FA activation generate **10 single-use recovery codes** (shown once, stored hashed).
- Require 2FA on every login from a new device and for sensitive actions (step-up).
- 2FA deactivation only with full re-authentication.

## Sessions and tokens
- See the hardening-siti skill for cookies. Additionally: invalidate all sessions on password change; "connected devices" list with revocation.
- If using JWT: short expiry (15 min) + revocable refresh token stored server-side; pinned algorithm (no `alg: none`).

## Account recovery
- Password reset via single-use expiring link/code, NEVER security questions.
- Email notification for every sensitive event: login from a new device, password/email change, 2FA activation/deactivation.

## Never do
- Send passwords via email. Log passwords or OTP codes. Reveal whether an email is registered (enumeration). Roll your own crypto.
