---
name: privacy-pagamenti
description: Protegge dati di pagamento e abbonamenti quando un sito/app gestisce checkout, carte, subscription o fatturazione. Copre Stripe/PayPal sicuri, verifica firma webhook, PCI-DSS, GDPR e ciclo di vita abbonamenti. Trigger - "pagamenti", "checkout", "abbonamento", "Stripe", "PayPal". EN - Protects payment and subscription data when a site/app handles checkout, cards, subscriptions or billing. Covers secure Stripe/PayPal integration, webhook signature verification, PCI-DSS, GDPR, data minimization and subscription lifecycle. Triggers - "payments", "checkout", "subscription", "Stripe", "PayPal", "credit card", "billing".
---

# Privacy Pagamenti e Abbonamenti · Payments Privacy

> 🇮🇹 Versione italiana qui sotto · 🇬🇧 [English version below](#payments--subscriptions-privacy-english)

Quando un sito/app gestisce pagamenti o abbonamenti, applicare queste regole.

## Regola d'oro: mai toccare i dati della carta
- Il numero di carta NON deve mai transitare dal proprio server né essere salvato nel proprio DB (requisito PCI-DSS). Usare sempre checkout/elementi ospitati dal provider: Stripe Checkout / Payment Element, PayPal Smart Buttons.
- Nel DB salvare SOLO: ID cliente del provider (es. `cus_...`), ID abbonamento, stato, ultime 4 cifre e brand se forniti dal provider.
- Le chiavi segrete (`sk_...`, client secret) vivono solo in variabili d'ambiente lato server. Nel frontend solo chiavi pubblicabili.

## Webhook: sempre verificati
Lo stato di pagamenti/abbonamenti si aggiorna SOLO da webhook verificati, mai dal redirect del browser (falsificabile).

```js
// Stripe (Express) — il body deve essere RAW
app.post('/webhook', express.raw({type: 'application/json'}), (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) { return res.status(400).send('Firma non valida'); }
  // gestire event.type: checkout.session.completed, invoice.paid,
  // invoice.payment_failed, customer.subscription.deleted ...
  res.json({received: true});
});
```

Per PayPal usare l'API di verifica firma webhook. Rendere i gestori idempotenti (stesso evento ricevuto due volte = nessun doppio effetto): salvare gli `event.id` processati.

## Abbonamenti
- Gestire sempre: pagamento fallito (grace period + email), cancellazione (accesso fino a fine periodo), upgrade/downgrade con proratazione del provider.
- La cancellazione deve essere facile quanto l'iscrizione (obbligo in UE/USA). Prevedere pagina "gestisci abbonamento" (Stripe Customer Portal è la via più semplice).
- Prezzi e importi: mai fidarsi di valori inviati dal client; il server usa solo i Price ID configurati.

## Privacy e GDPR
- **Minimizzazione**: raccogliere solo i dati necessari alla transazione. Niente dati di pagamento nei log, negli URL, in analytics o in email.
- **Informativa**: privacy policy che dichiara provider di pagamento, dati trattati, conservazione. Cookie banner se ci sono cookie non tecnici.
- **Diritti**: prevedere export ed eliminazione dei dati su richiesta (l'eliminazione lato provider va richiesta via API del provider). Conservare i dati di fatturazione per gli obblighi fiscali (in Italia 10 anni) separandoli dal profilo eliminato.
- **Cifratura**: TLS ovunque; dati personali sensibili cifrati at-rest se il DB lo consente.
- **Audit log**: registrare chi/quando per ogni evento di pagamento e modifica di abbonamento (senza PAN o dati carta).

## Checklist consegna
Chiavi in env, webhook con firma verificata e idempotente, nessun dato carta nel DB/log, portale di gestione abbonamento, privacy policy, flusso di cancellazione, gestione pagamento fallito.

---

# Payments & Subscriptions Privacy (English)

When a site/app handles payments or subscriptions, apply these rules.

## Golden rule: never touch card data
- The card number must NEVER pass through your server nor be stored in your DB (PCI-DSS requirement). Always use provider-hosted checkout/elements: Stripe Checkout / Payment Element, PayPal Smart Buttons.
- In the DB store ONLY: the provider's customer ID (e.g. `cus_...`), subscription ID, status, last 4 digits and brand if supplied by the provider.
- Secret keys (`sk_...`, client secrets) live only in server-side environment variables. Frontend gets publishable keys only.

## Webhooks: always verified
Payment/subscription state is updated ONLY from verified webhooks, never from the browser redirect (forgeable). Use the snippet above — the body must be RAW for signature verification.

For PayPal use the webhook signature verification API. Make handlers idempotent (same event received twice = no double effect): store processed `event.id`s.

## Subscriptions
- Always handle: failed payment (grace period + email), cancellation (access until period end), upgrade/downgrade with provider proration.
- Cancelling must be as easy as subscribing (mandatory in EU/US). Provide a "manage subscription" page (Stripe Customer Portal is the simplest route).
- Prices and amounts: never trust client-sent values; the server only uses configured Price IDs.

## Privacy and GDPR
- **Minimization**: collect only the data needed for the transaction. No payment data in logs, URLs, analytics or emails.
- **Notice**: privacy policy declaring the payment provider, processed data, retention. Cookie banner if non-essential cookies exist.
- **Rights**: provide data export and deletion on request (provider-side deletion must be requested via the provider's API). Keep billing data for tax obligations (10 years in Italy), separated from the deleted profile.
- **Encryption**: TLS everywhere; sensitive personal data encrypted at rest if the DB allows it.
- **Audit log**: record who/when for every payment event and subscription change (no PAN or card data).

## Delivery checklist
Keys in env, signature-verified idempotent webhooks, no card data in DB/logs, subscription management portal, privacy policy, cancellation flow, failed-payment handling.
