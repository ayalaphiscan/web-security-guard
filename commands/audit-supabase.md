---
description: Audit di sicurezza e privacy di un progetto Supabase - RLS tabella per tabella, permessi, funzioni, storage, Auth, chiavi - con prove come utenti diversi e report. EN - Security and privacy audit of a Supabase project - RLS table by table, grants, functions, storage, Auth, keys - with tests as different users and a report.
---

Esegui un audit di sicurezza del progetto Supabase collegato al progetto della cartella di lavoro. Se non c'è una cartella connessa, chiedila con request_cowork_directory (in Claude Code: lavora nella cartella corrente o chiedi il percorso). Usa le skill supabase-sicuro, api-sicura e privacy-posizione. Rispondi nella lingua dell'utente.

**Regole**
- In produzione si fanno solo letture: query sui cataloghi, oppure prove dentro un blocco che finisce sempre con `raise exception 'DRY RUN OK'`, così ogni modifica si annulla.
- Non modificare dati reali.
- Non stampare chiavi o segreti.
- Nelle prove in produzione restituisci solo conteggi o sì/no, mai il contenuto delle righe: i dati delle persone (messaggi, posizioni, dati dell'art. 9) non devono finire nel report. Impersona account di prova dedicati, non persone reali.
- Prima di provare scritture, controlla che nessun trigger chiami l'esterno (`http`, `pg_net`, `dblink`): il rollback non annulla una richiesta già partita né l'avanzamento delle sequenze.
- Se c'è un Postgres locale, le prove che scrivono si fanno lì, ripetendo le migrazioni della repository.

**Inventario**
1. Tabelle e viste esposte (`public` e altri schemi esposti all'API), con RLS sì/no e le policy (`pg_policies`).
2. Permessi di `anon` e `authenticated` su ogni tabella, anche per colonna.
3. Funzioni chiamabili (`has_function_privilege`) con `security definer`/`invoker` e `search_path`.
4. Bucket di storage (pubblici o no, tipi e dimensioni ammessi) e policy di `storage.objects`.
5. Impostazioni di Auth visibili (`/auth/v1/settings`) e quelle da controllare nella dashboard.
6. Chiavi presenti nel frontend: devono essere solo publishable/anon.
7. Security Advisor e Performance Advisor.

**Prove**, ognuna in due direzioni (chi deve riesce, chi non deve viene fermato):
- **lettura di righe altrui**: profili privati, messaggi, notifiche, richieste, posizioni;
- **scrittura a nome di altri**: insert e update con il proprietario cambiato;
- **colonne privilegiate**: verificato, piano, ruolo, contatori, stato;
- **RPC con l'id di un altro utente**;
- **cosa vede `anon`**, cioè solo con la chiave pubblica;
- **storage**: sovrascrivere o cancellare file altrui, caricare HTML o SVG in un bucket pubblico;
- **posizioni**: esatte o arrotondate nel database, oracoli di distanza;
- **enumerazione**: email o nickname esistenti, elenchi completi di utenti.

**Report**: salvalo come `supabase-audit.md` negli outputs e presentalo con present_files (in Claude Code: scrivilo nella cartella del progetto). Deve contenere:
- un riepilogo per gravità (Critica, Alta, Media, Bassa);
- per ogni problema: l'oggetto SQL o il file, la prova fatta e il risultato, perché è pericoloso in parole semplici, e la correzione come migrazione SQL pronta, con `grant` espliciti e RLS;
- la lista di ciò che è stato controllato e va bene.

Alla fine chiedi se applicare le correzioni. Se sì, scrivi le migrazioni nella repository, provale prima in locale o a vuoto, poi applicale e ricontrolla gli advisor.

---

*English: audit the Supabase project linked to the working folder's project (ask for the folder with request_cowork_directory if missing), using the supabase-sicuro, api-sicura and privacy-posizione skills; reply in the user's language.*

*Rules: production is read-only, apart from test blocks that always end with `raise exception 'DRY RUN OK'`. Never modify real data or print keys. Production tests return only counts or booleans, never row contents, and impersonate dedicated test accounts; first check that no trigger calls out (`http`, `pg_net`, `dblink`), which a rollback cannot undo. Run write tests on a local Postgres replaying the repo's migrations when one is available.*

*Inventory: exposed tables and views with their RLS and policies; anon/authenticated grants, including per column; callable functions with definer/invoker and search_path; storage buckets and policies; visible Auth settings and the ones to check in the dashboard; keys in the front-end; the advisors.*

*Tests, each both ways: reading other users' rows; writing on behalf of others; privileged columns; RPCs called with another user's id; what anon can read; overwriting or deleting other users' files and uploading HTML/SVG; exact positions and distance oracles; enumeration of emails, usernames and user lists.*

*Report `supabase-audit.md`: counts by severity; for each finding the object, the test and its result, the risk in plain words, and a ready SQL migration with explicit grants and RLS; the list of what was checked and found fine. Finally ask whether to apply the fixes (tested first, then applied, then advisors re-checked).*
