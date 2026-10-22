---
description: Guida passo passo in caso di incidente di sicurezza - contenere, conservare le prove, chiudere la falla, ripristinare, avvisare (anche il Garante entro 72 ore) - per siti e app con servizi gestiti. EN - Step-by-step guide during a security incident - contain, preserve evidence, fix, restore, notify (incl. the supervisory authority within 72 hours) - for sites and apps on managed services.
---

C'è (o potrebbe esserci) un incidente di sicurezza. Guida l'utente con calma, un passo alla volta, usando la skill risposta-incidenti. Rispondi nella lingua dell'utente. Annota ogni azione con l'ora in un file `incidente-<data>.md` negli outputs: servirà per il registro delle violazioni e per un'eventuale notifica.

1. **Capire in due minuti.**
   - Cosa è successo e da quando?
   - Quali dati o sistemi sono coinvolti? Account, database, chiavi, sito, email.
   - L'attacco è in corso?

   Assegna una gravità con la tabella della skill.
2. **Contenere** (prima di indagare a fondo), con le leve del progetto:
   - sito in manutenzione senza nuovo codice: interruttore, pagina di manutenzione o lockdown del guardian;
   - iscrizioni sospese dal fornitore di Auth;
   - account abusivi bloccati;
   - sessioni revocate e chiavi ruotate (publishable/secret, segreto JWT, token dei fornitori) se possono essere uscite. Prima di cancellare le sessioni copiane il contenuto (`auth.sessions`, `auth.refresh_tokens`): sono le prove migliori;
   - un permesso pericoloso tolto con una migrazione d'emergenza.

   Prima di ogni azione che cambia la produzione, chiedi conferma all'utente e spiega cosa smetterà di funzionare.
3. **Conservare le prove**: esporta subito i log (database, Auth, hosting, CDN) prima che scadano. Fai uno snapshot o un backup dello stato attuale. Non cancellare file sospetti: spostali.
4. **Chiudere la falla**: trova la causa (`/security-audit`, `/audit-supabase`), correggi, prova e rilascia. Ruota ogni segreto che può essere stato visto.
5. **Ripristinare**: se dei dati sono stati alterati o cancellati, ripristina da backup o PITR in un ambiente separato, confronta, poi riporta in produzione. Riapri il sito solo quando la falla è chiusa.
6. **Avvisare**: se sono coinvolti dati personali, valuta con l'utente la notifica all'autorità di controllo (in Italia il Garante privacy) entro 72 ore da quando si è venuti a conoscenza della violazione (GDPR art. 33, par. 1). Se il rischio per le persone è alto, avvisa anche loro (art. 34). Prepara le bozze di entrambe. In ogni caso registra la violazione nel registro interno (art. 33, par. 5).
7. **Dopo**: scrivi un post-mortem senza colpe (cronologia, causa, cosa ha funzionato, azioni con responsabile e data) e aggiorna il runbook.

Se l'utente non ha accesso a una console o manca la 2FA, segnalalo come primo punto delle azioni successive (skill account-fornitori).

---

*English: a security incident is (or may be) happening. Guide the user calmly, one step at a time, with the risposta-incidenti skill; reply in the user's language. Log every action with its time in `incidente-<date>.md` in outputs.*

*Steps:*
1. *Two-minute triage: what happened, since when, which data or systems, is it ongoing, severity.*
2. *Contain before deep investigation: maintenance without a deploy; pause sign-ups; block abusive accounts; revoke sessions (copy `auth.sessions` and `auth.refresh_tokens` first: they are the best evidence) and rotate keys that may have leaked; remove a dangerous grant with an emergency migration. Confirm every production change first.*
3. *Preserve evidence: export logs before they expire, snapshot, move (don't delete) suspicious files.*
4. *Fix the cause (`/security-audit`, `/audit-supabase`) and rotate exposed secrets.*
5. *Restore altered data from backup or PITR via a separate environment; reopen only when fixed.*
6. *Notify: GDPR art. 33 notification to the supervisory authority within 72 hours of becoming aware of it when personal data is involved; art. 34 to the people when the risk is high; the internal breach register (art. 33(5)) always. Draft both notices.*
7. *Blameless post-mortem and runbook update. A missing console access or 2FA is the first follow-up (account-fornitori skill).*
