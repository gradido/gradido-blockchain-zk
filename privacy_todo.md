# Privacy-Umbau: Gradido als Privacy Coin (halo2)

**Status:** Konzept, keine Implementierung. **Stand:** 2026-09-11. **Branch-Kontext:** `flat_complete_tx`

Ausgangslage: Eine produktive Chain gibt es noch nicht. Die bisher DB-gestützten
Transaktionen werden beim Start ins Blockchain-Format migriert
(`../gradido/dlt-connector/src/migrations/db-v2.7.0_to_blockchain-v3.7`). Im bisherigen
Blockchain-Format lägen sie vollständig offen im Hiero-Topic und in den Blockdateien —
deshalb startet die Chain direkt im abgeschirmten Format, und die Historie wird als
Genesis nur über den GradidoNode veröffentlicht, nicht über Hiero (E17).

Ziel:
Angestrebt ist ein abgeschirmtes Modell nach Vorbild von Zcash/Orchard, bei dem ein
halo2-Beweis öffentlich belegt, dass alle Regeln aus `src/interaction/validate/` eingehalten
sind, ohne Beträge, Adressen oder Beziehungen preiszugeben — mit Ausnahme der Schöpfung,
die bewusst öffentlich prüfbar bleibt (E7).

---

## 1. Überblick für Menschen

Das bisherige Blockchain-Format funktioniert wie ein offenes Kontobuch: Jede Transaktion nennt Absender,
Empfänger und Betrag im Klartext, und der Node rechnet Salden aus der Historie nach.
Das ist der Grund, warum sich nichts löschen lässt — die Historie *ist* der Zustand.

Der Umbau ersetzt das Kontobuch durch verschlüsselte "Notes" (Geldscheine). Statt eines
Saldos besitzt man eine Menge solcher Notes. Beim Bezahlen werden alte Notes entwertet
und neue erzeugt, und ein Nullwissen-Beweis belegt öffentlich, dass dabei alles mit rechten
Dingen zuging: dass die Notes echt sind, dem Ausgebenden gehören, noch nicht ausgegeben
wurden, und dass Summe rein = Summe raus. Sichtbar bleibt nur, *dass* eine Transaktion
stattfand — nicht zwischen wem und über wie viel.

Vier Dinge machen Gradido dabei anders als Zcash, und alle vier sind lösbar:

- **Der Decay.** Guthaben zerfällt mit der Zeit, ein Betrag ist also eine Funktion des
  Zeitpunkts. Gelöst, indem Notes ihren Wert *ankernormiert* speichern (siehe E2). Damit
  ist der Zerfall im Beweis kostenlos und die Werterhaltung wieder simple Addition.
- **Die Schöpfung.** Sie bleibt bewusst öffentlich, damit sich die Produktivität einer
  Community von außen plausibilisieren lässt — etwa wenn Gradido in einem Land als Währung
  eingeführt wird. Sichtbar sind Betrag, Datum, eine grobe Kategorie (Status, Lokal, Werk),
  der unterzeichnende Moderator, eine Empfangsadresse, die jeden Monat wechselt, und bei
  Werken das Projekt. Ein Werk wird von der Allgemeinheit finanziert, ähnlich wie mit
  Steuergeld — deshalb ist öffentlich, wie viel dafür geschöpft wurde. Was der Mensch danach
  mit dem Geld macht, bleibt privat. Das Limit von 1000 GDD prüft der Node
  wie heute, nur pro Monatsadresse. Der Verwendungszweck ist verschlüsselt, aber so
  gebunden, dass er sich nachträglich nicht ändern lässt (siehe E7, E15).
- **Die Verwahrung.** Die meisten Nutzer können keine Schlüssel verwalten, die Community
  hält sie. Gelöst durch die Aufteilung der Orchard-Schlüsselhierarchie: Der Server bekommt
  nur, was er zum Beweisen und Anzeigen braucht, das Nutzergerät behält allein die
  Ausgabeberechtigung. Die Community kann dann sehen, aber nicht stehlen.
- **Das Adressregister entfällt.** Heute prüft der Node bei jeder Zahlung, ob der Empfänger
  angemeldet ist. Zcash kennt so etwas nicht, dort ist jede richtig geschriebene Adresse
  empfangsbereit — und so laufen Überweisungen künftig auch: Jeder kann sich beliebig viele
  neue Adressen anlegen, ohne dass das irgendwo sichtbar wird. Vor Tippfehlern schützt eine
  Prüfsumme in der Adresse (siehe E14).

Was der Umbau kostet: Eine Transaktion wächst von einigen hundert Byte auf etwa 5 KB.
Was er zurückgibt: Der größte Teil davon ist nach der Prüfung löschbar, und weil Notes
durch den Decay ein natürliches Ablaufdatum haben, darf sogar die Doppelausgabe-Sperrliste
altern. Die Chain erreicht damit einen stationären Zustand, statt wie bei Bitcoin ewig zu
wachsen.

Was er *nicht* leistet: Gegenüber der eigenen Community bleiben verwahrte Nutzer sichtbar,
solange diese den Beweis erstellt. Der Gewinn liegt gegenüber fremden Communities,
Node-Betreibern und der Öffentlichkeit — und das ist datenschutzrechtlich die schwierige
Zeile, weil Cross-Community-Transfers im bisherigen Format alles gegenüber einer fremden
Organisation offenlegen. Schöpfungen bleiben absichtlich öffentlich (E7).

---

## 2. Eckpunkte (Entscheidungen)

Nummeriert, damit referenzierbar.

### E1 — Stack
halo2 (`halo2_proofs` + `halo2_gadgets`), Pasta-Kurven, IPA, **kein Trusted Setup**.

> **Stand:** dieses Repository (`gradido-blockchain-zk`) enthält die Action mit exaktem Decay
> (k=11), Schlüssel, Adressen, Notenverschlüsselung, Signaturen, Commitment-Tree, Bundle,
> Wire-Format, C-ABI für den Node und den Signer als WebAssembly. Transfer mit 2 Actions:
> ~700 ms beweisen, 7 ms prüfen, 9,9 KB. Details, Messwerte und Security Review in `README.md`.
Gadgets aus `orchard` übernehmen (Sinsemilla-Merkle, Poseidon, ECC, NoteCommit, Nullifier,
SpendAuth-Rerandomisierung) — ca. 70 % wiederverwendbar. Als Rust-Crate `gradido-blockchain-zk` mit
C-ABI, Muster analog `iota_rust_clib`. Richtwerte Orchard: k≈11, Proof ~3 KB, Beweis 1–3 s
nativ, Verifikation 10–50 ms.

### E2 — Werte ankernormiert speichern (**wichtigste Einzelentscheidung**)
Note speichert nicht den Nominalbetrag, sondern

```
u = amount_gddCent · 2^((t − DECAY_START_TIME) / SECONDS_PER_YEAR)
```

mit `DECAY_START_TIME = 1620927991`, `SECONDS_PER_YEAR = 31556952` (beides `unit.c`).

- Werterhaltung `Σ u_in = Σ u_out` gilt zu jedem Zeitpunkt → **kein `2^-x` im Circuit**,
  der komplette r128/fp256-Fixpunktapparat entfällt aus dem Beweis.
- Wertebereich ~160 Bit (64 gddCent + 63 Jahre + ~32 Fraktionsbits) → ein Pallas-Feldelement,
  Range-Checks per 16-Bit-Lookups.
- Nominale Schwellen (Schöpfungslimit) prüft der **Node** öffentlich; die Schöpfung ist
  öffentlich, der Node rechnet den nominalen Betrag selbst exakt wie heute in `u` um (E7).
  Kein Circuit vergleicht mehr gegen nominale Werte. Falls doch nötig: Decay-Faktor als
  Public Input, im Circuit bleibt eine Multiplikation.
- Vorarbeit ohne ZK möglich und empfohlen: `GradidoUnit` intern auf ankernormierte Werte
  umstellen, klassisch testbar. Riskantester Refactor, deshalb zuerst.

### E3 — Zeitbindung an `created_at`, nicht `confirmed_at`
Der Beweis entsteht **vor** dem Konsens, kann also nicht an den Konsens-Timestamp binden.
Er bindet an `created_at` (öffentlich im Body) + Sighash. Der Node prüft weiterhin
öffentlich `|confirmed_at − created_at| ≤ 120 s`
(`MAGIC_NUMBER_MAX_TIMESPAN_BETWEEN_CREATING_AND_RECEIVING_TRANSACTION`). Unverändert
gegenüber heute. Gilt nur für über Hiero geordnete Tx; migrierte Tx (E17) haben feste,
historische Zeitstempel.

### E4 — Datenmodell
```
Note = (community_id, coin_community_id, note_kind, d, pk_d,
        value, t_note, expiry_epoch, memo_cm, rho, rseed)
cm   = Poseidon(community, coin_community, value|t_note, kind|expiry,
                g_d, pk_d, rho, psi, memo_cm, rcm)
nf   = Poseidon(nk, rho, cm)
ivk  = Poseidon(ak_x, nk, rivk)          -- im Circuit abgeleitet
```
(Stand `gradido-blockchain-zk`, Circuit-Version 2.)
- `(d, pk_d)`: Orchard-Adresse mit Diversifier (E14), `pk_d = [ivk]·g_d`. Committet wird
  `g_d`, nicht `d` (wie Orchard): sonst könnte jeder, der eine Note kennt, sie mit
  `g_d := pk_d` ausgeben. `value` hat 63 Bit (int64 ≥ 0), `note_kind` 1 Bit.
- `rho` einer Transfer-Note ist der Nullifier der ausgegebenen Note, `rho` einer Schöpfung
  wird aus ihrer Tree-Position abgeleitet (gleiche Schöpfungsfelder ergeben trotzdem
  verschiedene Notes).
- `community` ist öffentlicher Input des Proofs; bis Cross-Community-Transfers kommen gilt
  `coin_community = community` für alle Notes einer Action.
- `note_kind ∈ {normal, deferred}` ersetzt `addr_type`. Einen Adresstyp des Empfängers
  kann niemand mehr zertifizieren (kein Register, E14).
- `memo_cm`: bindet das Memo (E15).

Node hält pro Community statt `account_balances` / `AddressIndex` / `PublicKeyDictionary`:
Note-Commitment-Tree (inkrementell, Tiefe 32) + Anchor-Root-Historie + Nullifier-Set (LMDB).

**Empfänger und `note_kind` einer Output-Note schreibt der Sender.** Bei Transfers ist das
gewollt (jede gültige Adresse). Schöpfungs-Notes sind komplett öffentlich, der Node
berechnet ihr `cm` selbst (E7).

Entfallen für abgeschirmte Tx: `calculateAccountBalance`, `getAddressType`-Filter,
`TransactionsIndex` nach Pubkey, die gesamte Saldo-Rekonstruktion. Das ist der große
Vereinfachungsgewinn. `calculateCreationSum` bleibt, gerechnet pro Schöpfungsadresse (E7).

### E5 — Custody-Split (Server beweist, Gerät autorisiert)
In Orchard ist `spend_auth_sig` eine Signatur über den Sighash mit `rk = ak + [α]G`.
Der Prover braucht nur den **öffentlichen** Punkt `ak`; `ask` geht **nicht** in den Witness.

| | hält | kann |
|---|---|---|
| Community-Server | `fvk` (`ak`,`nk`,`ivk`,`ovk`) | entschlüsseln, Salden zeigen, scannen, **Proof bauen** |
| Nutzergerät | Spending Key (daraus `ask`, `ivk`, `ovk`) | Transaktion **prüfen**, Ausgabe **autorisieren** |

**Das Gerät signiert nie blind** (`src/signer.rs`). Ein Hash vom Server würde einem
kompromittierten Server erlauben, eine Zahlung an Bob gegen eine an sich selbst zu tauschen.
Der Server schickt stattdessen einen `SigningRequest`: die `body_bytes`, die Öffnung jeder
erzeugten Note und die `α` der echten Spends. Das Gerät
1. rechnet den Sighash selbst: BLAKE2b-256 über `body_bytes` (`Gradido_BodySigh`),
2. akzeptiert nur einen Body mit genau einem lokalen Shielded Transfer, ohne fremde Felder,
3. prüft pro Output: Commitment = `cm_x` im Body, Ciphertexts = Verschlüsselung der Öffnung
   (unter dem eigenen `ovk`), Memo passt zu `memo_cm`,
4. zeigt Zahlungen an fremde Adressen (Betrag, Memo) und Wechselgeld an eigene Adressen,
5. signiert nur Actions, deren `rk` aus dem eigenen `ak` stammt.
Das reicht, weil jede erzeugte Note geprüft wird und Proof plus Binding-Signatur die Summe
garantieren. Nicht geprüft: die versiegelten Memos in `TransactionBody.memos` und die Güte
von `rseed` — beides kann Memo-Text bzw. Privatsphäre kosten, kein Geld. Voraussetzung: der
Signier-Code kommt **nicht** vom Community-Server (App oder Erweiterung, keine ausgelieferte
Webseite). Für Wallet-App oder Erweiterung gibt es das Modul als WebAssembly mit
JavaScript-Schnittstelle (`src/wasm.rs`, 149 KB gzip).

Folgen: keine unilaterale Bewegung durch die Community, kein In-Browser-Proving nötig
(Gerät prüft und signiert, rechnet keinen Proof), Recovery muss nur `ask` wiederherstellen (Guardians / soziale
Wiederherstellung) — der Note-Zustand liegt beim Server und geht nie verloren.

**Harte Regel:** *kein Community-Secret in den Witness*. Dann ist Custody eine reine
Deployment-Entscheidung pro Nutzer statt eines Protokoll-Forks.

### E6 — Zwei Custody-Stufen, ein Circuit, eine Anonymity-Set
`GRDT_ADDRESS_COMMUNITY_HUMAN` (verwahrt) und `GRDT_ADDRESS_CRYPTO_ACCOUNT`
("user control his keys", `address.h`) nutzen **dasselbe** Note-Format, denselben Tree,
denselben Circuit. Unterschied nur, wer `ivk`/`ask` hält — off-chain nicht sichtbar.
Beide Gruppen teilen sich eine Anonymity-Set; die verwahrte Masse ist die Deckung, in der
Selbstverwahrer verschwinden. Getrennte Pools wären für beide Seiten schlechter.
Keine der beiden Gruppen braucht für Transfers eine Registrierung (E14).

### E7 — Öffentliche Schöpfung (Muster ZIP 213)
Regel heute: `≤ 1000 GDD` pro Konto pro Zielmonat (`V02_TargetDateAlgoRole`, V01: 3000),
Einzelbetrag `0.2 … 1000 GDD`, Zieldatum in `[created_at − 2 Monate, created_at]`
(historisch 3 Monate zwischen 1585544394 und 1641681224).

**Anforderung:** Schöpfungen müssen von außen plausibilisierbar sein — z. B. wenn Gradido in
einem Land als Währung eingeführt wird und geprüft wird, ob die Leistung einer Community zu
ihrer Mitgliederzahl passt. Was der Mensch danach mit dem Geld macht, bleibt privat.

**Öffentlich pro Schöpfung:** Betrag, Zieldatum, `created_at`, ausstellende Community,
Kategorie, bei Werken der Projektbezug, Empfangsadresse, Signierer (Moderator, E16),
`memo_cm`.

**Kategorien** — grob, bewusst ohne Unterart:

| Kategorie | Beispiele | zusätzlich öffentlich |
|---|---|---|
| Status | Kind, Rente, Krankheit, … — *welcher* Status steht nur im Memo | — |
| Lokal | Straße fegen, Landwirtschaft, Pflege vor Ort | — |
| Werk | Bücher, Musik, Software, Erfindungen — alles Vervielfältigbare | Projektbezug (Pflicht) |

Die Status-Unterart gehört ins verschlüsselte Memo: "krank" wäre ein Gesundheitsdatum
(Art. 9 DSGVO) und in kleinen Communities zusammen mit lokalem Wissen personenbeziehbar.
Die Kategorie Werk ist die, bei der Doppelschöpfung über Community-Grenzen droht: Ihr
Ergebnis kann mehreren Communities zugutekommen. Abgrenzung zu ortsunabhängigen,
nicht vervielfältigbaren Leistungen: offene Frage 17.

**Schöpfungs-Note komplett öffentlich** (Muster Zcash ZIP 213, "Shielded Coinbase"):
- Die Tx enthält Adresse `(d, pk_d)`, Betrag, `rseed` und `memo_cm` im Klartext. Der Node
  rechnet `u` (E2) und `cm` selbst aus und hängt `cm` an den Note-Tree.
  **Kein Beweis, kein Circuit B.**
- `rho` leitet der Node eindeutig aus Tx-Hash und Index ab. Es gibt keine Input-Note, deren
  Nullifier es liefern könnte; ohne diese Regel wären Notes mit gleichem `rho` möglich
  (Faerie Gold).
- Ausgeben bleibt privat: Der Nullifier braucht `nk`, niemand außer dem Besitzer kann ihn der
  Schöpfungs-Note zuordnen. Anonymity-Set beim Ausgeben = alle Notes.

**Monatlich wechselnde Schöpfungsadresse = Schöpfungs-ID.** Die Community verwendet pro
Mitglied und Zielmonat eine neue diversifizierte Adresse aus einem eigenen
Diversifier-Bereich (E14). Ohne `ivk` sind die Monatsadressen eines Mitglieds nicht
verknüpfbar; die Community sieht alle.
- Node prüft `Σ Betrag pro (Adresse, Zielmonat) ≤ 1000 GDD` — das heutige
  `calculateCreationSum`, nur pro Adresse statt pro Konto.
- Node-Regel: Eine Adresse empfängt Schöpfung nur für *einen* Zielmonat. Erzwingt den Wechsel.
- Einzelbetrag-Grenzen und Zieldatum-Fenster prüft der Node wie heute.
- Anzahl verschiedener Schöpfungsadressen pro Zielmonat ≈ Zahl schöpfender Mitglieder →
  Kennzahl für die Plausibilitätsprüfung.

**Projektbezug** (Kategorie Werk, **Pflicht**): stabile, öffentliche Projekt-Referenz, über
Communities hinweg gleich. Sie ist der einzige Schutz gegen Doppelschöpfung für ein
Projekt. Sichtbar werden die Summe der Schöpfungen pro Projekt und Monat über alle
Communities und die Zahl verschiedener Empfangsadressen. Das **erkennt** Überschöpfung
gegen die bekannte Teamgröße, **verhindert** sie aber nicht — dieselbe Person hat in zwei
Communities verschiedene Adressen.
- **Transparenz ist gewollt:** Ein per Schöpfung finanziertes Werk ist von der Allgemeinheit
  finanziert, vergleichbar mit Steuergeld oder einem geförderten Open-Source-Projekt. Wie viel
  die Beteiligten dafür bekommen, ist öffentlich — bei wenigen Beteiligten auch pro Person
  (nicht aber, was sie mit dem Geld machen). Wem das zu offen ist, finanziert das Projekt
  privat statt über Schöpfung.

**Was die Chain nicht mehr garantiert:** ein Schöpfungskonto pro Mensch. Eine Community
kann einem Menschen zwei Adressen pro Monat geben oder Scheinmitglieder anlegen. Schutz ist
die Plausibilität in der Größenordnung (Mitgliederzahl ↔ Leistung). Der Verlust gegenüber
einem kryptographischen Register ist klein: Auch dort hätte die Community die Identität
selbst berechnet und Scheinmitglieder registrieren können.
- Doppelmitgliedschaft (eine Person, zwei Communities): bei Werk über den Projektbezug
  erkennbar, bei Status nur durch die Communities selbst (offene Frage 15). Bei Lokal
  schützt die physische Anwesenheit.

**Signierer: öffentlich.** Ein Moderatorenschlüssel, den die Community per
`ModeratorUpdate` aktiviert und wieder deaktivieren kann (E16). Passt zur offiziellen
Prüfbarkeit und hält die Schöpfung vollständig beweisfrei. "Signierer ≠ Empfänger" ist
öffentlich nicht mehr prüfbar, weil der Empfänger nur eine Monatsadresse ist; die Community
kann es intern prüfen.

### E8 — Deferred Transfer auf Zeitschloss umstellen
`GradidoTimeoutDeferredTransfer` sowie `TransactionTriggerEvent` /
`createTransactionByEvent` / `findNextTransactionTriggerEventInRange` **ersatzlos streichen**.
Ein abgeschirmter Node kann Timeouts nicht mehr sehen.

Stattdessen: Deferred-Note trägt `timeout_at`; vor Ablauf vom Empfänger ausgebbar, nach
Ablauf vom Absender. Zeitschloss im Circuit gegen öffentliches `created_at`. Der
"Decay-Rest zurück an den Absender" wird in ankernormierten Einheiten exakt und gratis.
Spart erhebliche Node-Komplexität.

Gelöschte Transaktionslinks (`DeletedTransactionLinksSync.role.ts`) sind keine Lücke: Der
Eigentümer überweist sich den Betrag selbst zurück — er kennt das Link-Geheimnis und damit
den Empfängerschlüssel.

### E9 — Ledger ordnet nur, der GradidoNode verwaltet
**Aufgabenteilung:**
- **Hiero/Hedera** ordnet neue Tx, damit alle Nodes dieselbe Reihenfolge sehen — und
  verteilt sie vorerst, bis das Peer-to-Peer-Gossip im GradidoNode fertig ist. Langfristig
  soll auch die Ordnung ersetzt werden (schwieriger).
- **GradidoNode** (`../gradido_node`) validiert, speichert und stellt alle Tx bereit —
  abgeschirmte Tx wie öffentliche Schöpfungen. Historische Tx laufen nie über Hiero (E17).

**Nichts Hiero-Spezifisches in die Public Inputs.** Der Beweis bindet an `created_at` +
Sighash über `body_bytes`, sonst nichts. `LedgerAnchor` mit seinem `oneof` abstrahiert die
Ledger-Identität bereits sauber und überlebt einen Wechsel unverändert.
Der Ledger **verifiziert keine Proofs** — er ordnet, der Gradido-Node validiert.

**Mit Gossip nur noch Hashes über Hiero:** Sobald der GradidoNode die Tx selbst verteilt,
muss Hiero nur noch den Tx-Hash (32 Byte) ordnen. Das löst Frage 8 (Nachrichtengröße,
Gebühren) und hilft der Privatsphäre: Was über Hiero läuft, liegt dauerhaft in den
Hedera-Mirror-Nodes und entzieht sich dem Pruning (E11) — auch verschlüsselte Ciphertexts.

Kontext: Hedera-Gebührenzahler ist die Community, nicht der Nutzer → **keine** Payer-Verlinkung
pro Nutzer on-chain. Verbleibt ein Relay-Aspekt (Community sieht Zeit/IP/Bytestrom beim Submit).
Langfristig soll Hedera ersetzt oder selbst gehostet werden.

### E10 — Note-Ablauf durch Decay (macht Pruning möglich)
`expiry_epoch` in der Note, Circuit erzwingt `current_epoch ≤ note.epoch + N`.
Danach unausgebbar → **ihr Nullifier darf gelöscht werden**. Das Nullifier-Set wächst damit
nicht mehr ewig, sondern erreicht einen stationären Zustand.

Begründung: eine unangetastete Note verliert 50 %/Jahr, `unit.c` liefert nach 63 Jahren
buchstäblich 0. Wallets wälzen Notes automatisch um, der Server tut das für seine Mitglieder.
Wer N Jahre nicht erscheint, hätte ohnehin fast nichts mehr. **N ist offen** (Vorschlag 5).

Zusatz: epochenweise Commitment-Trees → alte Bäume kollabieren auf einen Root, entschärft
zugleich das Witness-Update-Problem der Wallets.

### E11 — Drei Speicherschichten
| Schicht | Inhalt | Lebensdauer |
|---|---|---|
| Konsens | Nullifier-Set, Tree-Root/Frontier, RunningHash | permanent, mit E10 alternd |
| Validierung | Proof (~3 KB) | löschbar nach Prüfung |
| Empfänger | `enc_ciphertext` (~660 B/Action) | löschbar nach Scan |
| Memo | `memo_ciphertext` | löschbar; wer prüfen will, bewahrt Memo, Öffnung und Merkle-Pfad (E15) |

`ConfirmedGradidoTxCold` (Memos, SignatureMap, `bodyBytes`, RunningHash, LedgerAnchors,
schon optionaler `unique_ptr` hinter `loadColdData`) ist bereits fast exakt die prunbare
Menge — das ist die vorhandene Naht, an der Pruning ansetzt.

Für verwahrte Nutzer hält der Server ohnehin `ivk`, entschlüsselt beim Empfang sofort und
kann den Ciphertext danach fallen lassen. Nur Selbstverwahrer brauchen ein Scan-Fenster.

Größenordnung, Community mit 10.000 Aktiven à 5 Tx/Monat: Vollarchiv ~3 GB/Jahr,
gepruned ~38 MB/Jahr bzw. ~190 MB stationär bei N=5.

### E12 — Byte-Optimierung auf die permanente Schicht verlagern
Eine abgeschirmte Tx wird ~5 KB statt heute wenige hundert Byte — Faktor 10–20 auf genau
der Achse, die bisher optimiert wurde. Nicht wegzudesignen, nur zu prunen.
Die bestehende Arbeit (16-Byte-Unions, `PublicKeyIndex` statt Pubkey, Hot/Cold-Split) gilt
weiter, betrifft aber ab jetzt bewusst den **permanenten** Teil. Der flüchtige darf fett sein.

### E13 — Endgame: rekursiver Zustandsbeweis
halo2s Accumulation erlaubt einen rekursiven Beweis, dass der Zustand aus korrekter
Anwendung der Historie hervorgeht (Minas Konstruktion). Neu-Sync = Zustandswurzel + ein
Beweis statt der Kette. Nicht Phase 1, aber ein weiterer Grund für halo2 statt eines
SNARK-Stacks mit Trusted Setup.

Erster Anwendungsfall: die Genesis aus der Migration (E17) — ein Beweis statt vieler
Einzelproofs. Zwei Wege:
- **halo2-Rekursion:** theoretisch passend (Pasta-Zyklus), aber die zcash-halo2-Bibliothek
  enthält keine fertige Rekursion; auch Zcash fasst Proofs über Tx hinweg heute nicht
  zusammen (nur Batch-Verifikation).
- **zkVM** (z. B. RISC Zero, unterstützt C/C++, Beweise sind zero-knowledge): Der Gast spielt
  die Historie mit dem C-Code aus `gradido-blockchain-core` nach und veröffentlicht nur das
  Ergebnis. Zusammenfassen bringen zkVMs fertig mit. Ohne Groth16-Hülle kein Trusted Setup,
  der Beweis ist dann einige hundert KB groß — für einen einmaligen Beweis unkritisch.
  Unklar sind die Kosten der Orchard-Kryptographie (Pallas, Sinsemilla, Poseidon) ohne
  eingebaute Beschleuniger. Derzeit nicht verfolgt.
- Für den Beweis pro Tx bleibt halo2: zkVM-Beweise sind zu groß oder brauchen ein Trusted
  Setup, und das Beweisen braucht Grafikkarten.

### E14 — Adressen ohne Register
`RegisterAddress` erfüllt heute drei Aufgaben: Der Node prüft per `getAddressType`, dass der
Empfänger angemeldet ist (Schutz vor Tippfehlern), er kennt den Adresstyp (nur
`COMMUNITY_HUMAN` darf Schöpfung empfangen und signieren), und die drei Signaturen binden
Konto, Nutzer und Community aneinander.

Im abgeschirmten Modell steckt der Empfänger im `cm` — **der Node kann ihn nicht mehr
nachschlagen.** Zcash kennt gar kein Register: Adressen entstehen lokal, jede gültig
kodierte Adresse ist empfangsbereit, Geld an eine Adresse ohne Schlüsselinhaber ist verloren.

**Entscheidung: kein Empfängerregister.** Müsste jede Adresse registriert werden, wäre jede
neue Adresse öffentlich und mit den anderen Adressen desselben Menschen verknüpft. Das
widerspricht "Transfers komplett privat". Für die Schöpfung ersetzt öffentliche
Plausibilität den kryptographischen Nachweis (E7).

| Aufgabe | Lösung | Ebene |
|---|---|---|
| Tippfehlerschutz | Adresskodierung nach ZIP 316 (s. u.) | Wallet/Backend, kein Konsens |
| Transferempfänger | keine Prüfung, jede gültig kodierte Adresse | — |
| Schöpfungsberechtigung | Community-Signatur, öffentliche Summenprüfung pro Monatsadresse, Plausibilität (E7) | Node, öffentlich |
| Signierberechtigung | aktiver Moderatorenschlüssel (`ModeratorUpdate`, E16) | Node, öffentlich |
| Jemand hält den Schlüssel wirklich | optional Rückfrage an die Empfänger-Community per Federation (hält bei Verwahrten `ivk`) | off-chain |

**Verworfen:** ein HUMAN-Register mit Mitgliedschaftsbeweis (vormals Circuit B/C) und eine
Identität aus dem E-Mail-Hash auf der Chain. Gründe: Plausibilität statt Kryptographie (E7),
und keine aus E-Mails abgeleiteten Daten auf der Chain — ein geleakter Salt-Schlüssel
könnte sie sonst per Wörterbuch dauerhaft auf E-Mail-Adressen zurückführen. Der gesalzene
Hash der ersten E-Mail bleibt als Identifier **Community-intern** (Dublettenprüfung in der DB).

**Was aus `RegisterAddress` wird:** entfällt ersatzlos, ersetzt durch `ModeratorUpdate`
(E16). Es gibt keine alte Chain, deren Historie weiter validiert werden müsste.
Adresstypen: `SUBACCOUNT` wird zu Diversifier bzw. ZIP-32-Konto;
`CRYPTO_ACCOUNT` und `COMMUNITY_PROJECT` brauchen keine Registrierung mehr;
`COMMUNITY_GMW`/`COMMUNITY_AUF` bleiben über `CommunityRoot` definiert, jetzt als
Orchard-Adressen (`gmw_address`, `auf_address`), damit sie Notes empfangen können. `addr_type` in der
Note wird zur Note-Art (E4).

**Diversifizierte Adressen.** Ein Konto kann beliebig viele Adressen haben: Diversifier-Index
1, 2, … zu denselben Schlüsseln und demselben Saldo, ohne On-Chain-Ereignis. Öffentlich sind
sie untereinander nicht verknüpfbar. Der Server scannt alle mit einem `ivk`. Die monatlichen
Schöpfungsadressen (E7) kommen aus einem eigenen Diversifier-Bereich, damit sie nicht mit
Transferadressen kollidieren.

Zwei Ebenen, beide aus derselben Seed ableitbar (kein neues Backup):

| Ebene | Mechanismus | Saldo | heute |
|---|---|---|---|
| neue Adresse im Konto | Diversifier-Index | gemeinsam | — |
| neues Konto | ZIP 32 (für Orchard nach SLIP-0010 modelliert, nur gehärtet) | getrennt | `derivation_index` (SLIP-0010, Ed25519) |

SLIP-0010 selbst passt nicht, weil es Ed25519-Schlüssel ableitet, Orchard aber
Pallas-Schlüssel braucht. Übergang: Die Migration leitet heute alle Nutzerschlüssel aus dem
Community-Schlüssel ab (`deriveFromKeyPairAndUuid`); dieselbe Ableitung kann die ZIP-32-Seed
pro Nutzer liefern (E17).

**Adresskodierung** (Muster ZIP 316): `payload = d ‖ pk_d ‖ Community-Kennung`. HRP auf
16 Byte gepaddet anhängen, F4Jumble, Bech32m ohne 90-Zeichen-Limit. Beim Dekodieren:
Prüfsumme, Padding, `pk_d` gültiger Pallas-Punkt ≠ Identität. Zufällige Fehler fallen
praktisch sicher auf; F4Jumble verhindert zudem gefälschte Adressen mit passendem Anfang und
Ende. Zahlungsanforderungen per URI/QR (Muster ZIP 321) ersparen das Abtippen ganz.
Unabhängig vom ZK-Teil umsetzbar.

Nebeneffekt von E10: Eine Note an eine gültige, aber falsche Adresse zerfällt und läuft ab —
verlorenes Geld sammelt sich nicht dauerhaft an.

### E15 — Verbindliches Memo
Anforderung: Das Memo ist verschlüsselt, aber gebunden. Wer die nötigen Schlüssel hat, kann
nachprüfen, wofür das Geld gedacht war, und niemand kann es nachträglich ändern. Bei der
Schöpfung Pflicht.

Zcash leistet das **nicht**: Das Memo liegt in `enc_ciphertext`, `cm` bindet es nicht, und
niemand beweist, dass der Ciphertext stimmt.

Lösung: Memo-Commitment in der Note.
```
memo_cm         = H(memo ‖ r_memo)            // Feld der Note, geht in cm ein (E4)
memo_ciphertext = Enc(memo_key, memo ‖ r_memo)
```
- `r_memo` steht im Memo-Ciphertext, **nicht** im Note-Klartext: Schöpfungs-Notes sind
  öffentlich (E7), mit öffentlichem `r_memo` ließen sich kurze Memos per Raten aus `memo_cm`
  zurückgewinnen.
- Im Circuit nur ein Feldelement mehr in `NoteCommit`; das Memo selbst sieht der Circuit nicht.
- Prüfung: Memo und `r_memo` mit dem Memo-Schlüssel entschlüsseln → `memo_cm` nachrechnen →
  `cm` nachrechnen und mit der Chain vergleichen. Bei Transfers braucht das Öffnen von `cm`
  zusätzlich den View-Key; bei Schöpfungen ist die Note öffentlich, der Memo-Schlüssel
  genügt. Nachträglich ändern lässt sich das Memo so nicht.
- Pruning (E11) bleibt erlaubt: Weil `cm` bindet, darf `memo_ciphertext` von der Chain
  verschwinden, sofern der Prüfberechtigte Memo, Öffnung und Merkle-Pfad aufbewahrt. Den
  Pfad braucht er, weil alte Epochen-Trees nach E10 auf einen Root kollabieren.
- Grenze: garantiert *unverändert*, nicht *entschlüsselbar*. Ein Sender könnte Müll
  verschlüsseln — bemerkbar, nicht verhinderbar. Für Schöpfungen tragbar, weil die Community
  sie selbst erstellt. Sonst: Verschlüsselung im Circuit beweisen (Poseidon-basiert, Kosten
  wachsen mit der Länge, ~15 Feldelemente bei 450 Byte). Erst dann wären auch die
  Memo-Pflicht und die heutigen Längenregeln (5…450 Byte) beweisbar; bis dahin sind sie
  Policy der Community.
- Gilt für alle Notes gleich, kostet fast nichts.
- Offen: wer den Memo-Schlüssel hält (heute `SHARED_SECRET` für Sender/Empfänger,
  `COMMUNITY_SECRET` für alle Nutzer des Community-Servers).

### E16 — `ModeratorUpdate` statt `RegisterAddress`
Schöpfungen signiert ein öffentlicher Moderator (E7). Heute darf jeder Signierer mit
`COMMUNITY_HUMAN`-Konto schöpfen (`GradidoCreationRole.cpp:134-141`); künftig nur ein aktiver
Moderator. Die Variante "Prozent der Gruppenmitglieder" aus dem Kommentar in
`gradido_creation.proto` entfällt.

```protobuf
message ModeratorUpdate {      // Name nach Muster CommunityFriendsUpdate
  bytes moderator_pubkey = 1;  // Ed25519, signiert Schöpfungen über sig_map
  bool active = 2;             // true = aktivieren, false = deaktivieren
}
```
- **Signaturen:** immer der `CommunityRoot`-Schlüssel. Beim Aktivieren zusätzlich der
  Moderatorenschlüssel selbst — beweist, dass es den Schlüssel gibt und jemand ihn hält
  (kein Tippfehler, kein fremder Schlüssel). Beim Deaktivieren nur `CommunityRoot`, weil ein
  ausgeschiedener Moderator oder ein verlorener Schlüssel nicht mitwirken kann.
- **Zeitpunkt:** Entscheidend ist der Status des Moderators an der Stelle, an der die
  Schöpfung bestätigt wird (Chain-Reihenfolge, nicht `created_at`). Eine Schöpfung, die vor
  der Deaktivierung erstellt, aber danach bestätigt wird, ist ungültig — deterministisch,
  keine Grauzone im 120-s-Fenster (E3). Frühere Schöpfungen bleiben gültig.
- **`RegisterAddress` wird ersetzt, nicht parallel gehalten:** Es gibt keine alte Chain;
  die bisher DB-gestützten Transaktionen werden beim Start migriert. `ModeratorUpdate`
  übernimmt direkt den `oneof`-Platz von `register_address`.
- **Migration** (`../gradido/dlt-connector/src/migrations/db-v2.7.0_to_blockchain-v3.7`):
  `UsersSync.role.ts` erzeugt heute pro Nutzer ein `RegisterAddress` — entfällt. Stattdessen
  ein `ModeratorUpdate` für jeden Nutzer, der in der DB eine Schöpfung bestätigt hat
  (`contributions.confirmed_by`, von `CreationsSync.role.ts` schon als Signierer genutzt),
  vor seiner ersten Bestätigung.
- **`CommunityRoot` bleibt** und ist die einzige Quelle der Moderatoren-Berechtigung. Damit
  ist sein Schlüssel ein Single Point of Failure: Wer ihn hat, kann Moderatoren anlegen und
  unbegrenzt schöpfen. Heute hat `CommunityRoot` keine Rotation (offene Frage 19).
- Moderatoren sind öffentlich über ihren Schlüssel sichtbar, nicht über ihren Namen; wer
  hinter einem Schlüssel steht, weiß die Community.

### E17 — Migration: ganze Historie als Genesis im GradidoNode
**Entscheidung:** Jede historische DB-Transaktion wird ins Zielformat übersetzt — Transfers,
Links, Redeems als abgeschirmte Tx mit einem Proof pro Tx (Circuit A), Schöpfungen als
öffentliche Schöpfung (E7), Moderatoren per `ModeratorUpdate` (E16).

**Zugleich Vollständigkeitstest des Formats:** Die DB-Historie enthält jede Konstellation,
die es wirklich gab (Links mit Funding, Redeem, Löschen, Ablauf; Cross-Community-Tx;
V01-Schöpfungen; Decay-Grenzfälle). Jede Tx, die sich nicht übersetzen lässt, ist eine
Lücke im Format — gefunden vor dem Start.
Gegenprobe: Nach dem Durchlauf muss jeder Saldo in Notes centgenau dem DB-Saldo entsprechen.

**Nichts läuft über Hiero.** Die Reihenfolge der Historie steht fest; Hiero ordnet nur neue
Tx (E9). Die Historie wird ausschließlich über den GradidoNode veröffentlicht (Genesis-Paket).
- Historische Tx tragen die vorhandenen Anker `LEGACY_GRADIDO_DB_TRANSACTION_ID`,
  `…_USER_ID`, `…_CONTRIBUTION_ID`, `…_TRANSACTION_LINK_ID`, `…_COMMUNITY_ID` statt
  `HIERO_TRANSACTION_ID`, dazu ihre historischen Zeitstempel.
- Für Legacy-Anker gilt das 120-s-Fenster (E3) nicht; stattdessen prüft der Node die
  historischen Regeln (V01 3000 GDD, 3-Monats-Fenster). Der Decay des Altbestands ist schon
  mit der C-Decay-Funktion nachgezogen — keine Abweichung zur bisherigen Blockchain-Version.
- Cross-Community-Tx der Historie müssen in beiden Communities konsistent migriert werden
  (gleiches `cv`, passende Paarung).

**Genesis-Verankerung:** Die erste Tx, die über Hiero läuft, setzt auf der migrierten
Historie auf und nagelt sie damit fest. Kein zusätzlicher Anker nötig.

**Historische Schöpfungen werden öffentlich** wie alle Schöpfungen (E7): sichtbar ist nur,
dass eine Adresse zu einem Zeitpunkt GDD bekommen hat. Memos bleiben verschlüsselt; wem eine
Adresse gehört, lässt sich nur mit den Daten aus der Community-DB zuordnen. Für
Gradido-Nutzer waren die Schöpfungen anderer ohnehin schon lange einsehbar.
- Kategorie bleibt vorerst leer (`UNSPECIFIED`). Eine spätere Zuordnung (evtl. KI-gestützt)
  fließt einfach in den nächsten Migrationslauf ein.

**Wiederholbar bis zum Start:** Die Migration wird beliebig oft neu ausgeführt — erster Stand
zum Vorführen und Experimentieren, danach neue Läufe mit ergänzten Daten. Verbindlich ist
erst der letzte Lauf, auf den die erste Hiero-Tx aufsetzt.
- Empfehlung: alle Zufallswerte (`rseed`, `r_memo`, `esk`, `α`, Blinding der Proofs)
  deterministisch aus dem Community-Schlüssel und der DB-ID ableiten (PRF, Muster RFC 6979).
  Dann liefern zwei Läufe mit gleichen Eingaben bitgleiche Ergebnisse, und ein Diff zeigt
  genau, was sich geändert hat (z. B. nur Kategorien).

**Proofs:** Das Genesis-Paket enthält alle Einzelproofs; Nodes prüfen sie einmal per
Batch-Verifikation und dürfen sie danach löschen (E11). Später kann ein einziger Beweis die
Einzelproofs ersetzen (E13: halo2-Rekursion oder zkVM). Die Einzelproofs mit Circuit A
bleiben trotzdem nötig — nur sie testen, dass der *Circuit* alle Konstellationen abdeckt.

**Grenze:** Proofs belegen, dass jede Tx die Regeln einhält, nicht dass die DB-Historie wahr
ist. Eine Community könnte eine in sich stimmige Historie zwischen eigenen Schlüsseln
erfinden. Gegenüber Behörden garantiert die Öffentlichkeit aller Schöpfungen (E7) die
prüfbare Geldmenge.

Machbarkeit: Die Migration leitet alle Nutzerschlüssel aus dem Community-Schlüssel ab
(`deriveFromKeyPairAndUuid`), kann also jede historische Tx signieren und beweisen. Nach der
Migration wandert `ask` auf die Nutzergeräte (E5).

---

## 3. Bestehende Regeln → Ziel

Quelle: `src/interaction/validate/`

| Regel (heute) | wird zu |
|---|---|
| `TransferAmountRole`: Betrag > 0, Ed25519-Pubkey gültig | Range-Check `u > 0` in Circuit A |
| `GradidoTransferRole`: Sender ≠ Empfänger | strukturell trivial / entfällt |
| `GradidoTransferRole::validatePrevious`: Saldo reicht (+100 gddCent Toleranz) | **entfällt** — im Note-Modell unmöglich zu verletzen |
| `validateAccount`: Adresstypen ∉ {NONE, DEFERRED_TRANSFER} | **entfällt** (kein Register, E14); Deferred wird `note_kind` (E4) |
| Empfänger registriert (`getAddressType ≠ NONE`, u. a. Redeem) | **entfällt**; Transfer: nur Prüfsumme der Adresskodierung (E14) |
| Coin-Community-Gleichheit | `coin_community_id` in Note, Circuit A |
| `GradidoCreationRole`: 0.2 ≤ amount ≤ 1000 | **bleibt Node-Prüfung**, öffentlich (E7) |
| `GradidoCreationRole`: Monatslimit über `calculateCreationSum` | **bleibt Node-Prüfung**, pro (Monatsadresse, Zielmonat) (E7) |
| `validateTargetDate`: Zieldatum-Fenster | **bleibt Node-Prüfung**, öffentlich (E7) |
| `GradidoCreationRole`: Empfänger ist `COMMUNITY_HUMAN` | **entfällt** als Chain-Regel; Community-Signatur + Plausibilität (E7) |
| Signierer ist anderer `COMMUNITY_HUMAN` | Signierer ist aktiver, öffentlicher Moderator (E16); "≠ Empfänger" nur Community-intern prüfbar (E7) |
| neu: Kategorie, Projektbezug bei Werk, Adresse nur für einen Zielmonat | Node-Prüfung, öffentlich (E7) |
| `GradidoDeferredTransferRole`: Timeout 1 h … 3 Monate | Circuit A, Zeitschloss (E8) |
| `GradidoRedeemDeferredTransferRole`: vor Ablauf, Adresspaar passt | Circuit A, Note-Bindung + Zeitschloss |
| `GradidoTimeoutDeferredTransferRole` | **entfällt** (E8) |
| `RegisterAddressRole` (3 Sigs: account, user, community root) | **entfällt** ersatzlos, keine alte Chain (E14, E16) |
| neu: `ModeratorUpdateRole` | Signatur `CommunityRoot`, beim Aktivieren zusätzlich Moderator (E16) |
| `CommunityRootRole` | bleibt öffentlich; ihr Schlüssel signiert `ModeratorUpdate` (E16) |
| `GradidoTransactionRole`: Ed25519-Sigs über `body_bytes` | abgeschirmt: `spend_auth_sig` über Sighash mit rerandomisiertem `rk`; Schöpfung: bleibt |
| `ConfirmedTransactionRole`: RunningHash, 120s-Fenster, Anchor gesetzt | **bleibt unverändert** |
| Memo-Regeln (5…450 Byte, Plaintext-Erkennung) | Klartext-Regeln **entfallen** — feste Ciphertext-Länge, kein Längen-Leak; Memo per `memo_cm` gebunden (E15); Länge/Pflicht nur mit Verschlüsselung im Circuit beweisbar |

---

## 4. Circuits

### Circuit A — Action (Transfer / Deferred / Redeem), Arbeitspferd
- Merkle-Pfad jeder Input-Note zu öffentlichem Anchor-Root
- Nullifier-Ableitung (Doppelausgabe prüft Node gegen sein Set)
- Spend-Authority via `rk = ak + [α]G`
- Werterhaltung in ankernormierten Einheiten (E2), Range-Checks, `u > 0`
- `coin_community_id` über alle In-/Outputs identisch
- `note_kind`-Policy (Deferred nur über Zeitschloss)
- **keine** Register-Prüfung der Outputs — jede gültige Adresse (E14)
- `memo_cm` als Feld in `NoteCommit` (E15)
- Zeitschloss Deferred/Redeem gegen `created_at`
- `expiry_epoch`-Check (E10)

Schöpfungs-Notes werden hier ganz normal als Inputs ausgegeben.

**Stand `gradido-blockchain-zk` (Circuit-Version 2), noch nicht umgesetzt:** Zeitschloss für
Deferred/Redeem (E8) und `expiry_epoch`-Check (E10) — `note_kind` und `expiry_epoch` werden nur
committet und bereichsgeprüft; Cross-Community-Coins (bis dahin `coin_community = community`).

### Circuit B — Creation: **entfällt**
Die Schöpfung ist öffentlich, der Node rechnet `cm` selbst (E7), und der Signierer ist ein
öffentlicher Moderator (E16).

### Circuit C — Registrierung verdecken: **entfällt**
Es gibt kein Empfängerregister mehr (E14).

---

## 5. Protobuf-Änderungen

**Umgesetzt** in `../gradido_protocol/proto/gradido/` (Branch `v4.0`, noch nicht committet;
mit `pbtools` generierbar, erzeugter C-Code kompiliert). C-Strukturen im Core
(`dependencies/gradido-blockchain-core/.../data/proto/`) müssen neu generiert werden.
Keine Rückwärtskompatibilität nötig — es gibt keine alte Chain.

| Datei | Änderung |
|---|---|
| `shielded.proto` | **neu**: `Anchor`, `ShieldedAction`, `ShieldedBundle`, `ShieldedAuthorization` |
| `moderator_update.proto` | **neu**: `ModeratorUpdate { moderator_pubkey, active }` (E16) |
| `register_address.proto` | **gelöscht** (E14, E16) |
| `gradido_transfer.proto` | **gelöscht** — Transfer, Deferred, Redeem, Timeout gehen in `ShieldedBundle` auf |
| `transaction_body.proto` | `oneof data`: `shielded_transfer = 6` (`ShieldedBundle`), `creation = 7`, `community_friends_update = 8`, `moderator_update = 9`, `community_root = 11` |
| `gradido_transaction.proto` | neu `shielded_authorization = 4`; `sig_map` nur für öffentliche Tx |
| `gradido_creation.proto` | öffentlich, mit `recipient_address`, `amount`, `rseed`, `memo_cm`, `category`, `project_ref` (E7) |
| `confirmed_transaction.proto` | `account_balances` und `balance_derivation` entfallen; neu `note_commitment_tree_root = 7`, `first_note_position = 8` |
| `ledger_metadata.proto` | `NODE_TRIGGER_TRANSACTION_ID` (E8) und Enum `BalanceDerivation` entfallen |
| `basic_types.proto` | `AccountBalance`, `TransferAmount` entfallen; `EncryptedMemo.PLAIN` entfällt |
| `community_root.proto` | `pubkey` bleibt (Ed25519, signiert `ModeratorUpdate`); `gmw_pubkey`/`auf_pubkey` werden `gmw_address`/`auf_address` (43-Byte-Orchard-Adressen), damit GMW und AUF Notes halten können |

**Designentscheidungen dabei:**
- **Ein Typ für Transfer, Deferred und Redeem** (`shielded_transfer`). Getrennte öffentliche
  Typen würden verraten, dass ein Transaktionslink erstellt oder eingelöst wurde. Die Art der
  Note und das Zeitschloss stecken in der Note und werden vom Proof erzwungen (E8).
- **Aufteilung nach Sighash:** `ShieldedBundle` (Anchor, Actions, `cross_community_cv`,
  `circuit_version`) liegt im `TransactionBody` und ist damit über `body_bytes` signiert.
  `ShieldedAuthorization` (Proof, `spend_auth_sigs`, `binding_sig`) liegt in
  `GradidoTransaction` außerhalb der Signatur — wie bei Orchard, wo Proof und Signaturen nicht
  Teil des Sighash sind.
- **Memos:** `repeated EncryptedMemo` bleibt (mehrere Schlüsseltypen möglich, Frage 12), jetzt
  immer verschlüsselt, Inhalt `memo ‖ r_memo` in fester Länge, gebunden über `memo_cm` (E15).
- **`amount` in der Schöpfung** ist `GradidoUnit` (GDD · 10⁴), nominal; der Node rechnet den
  ankernormierten Notenwert (E2).
- **`BalanceDerivation` komplett gestrichen:** Der Altbestand ist mit der C-Decay-Funktion
  nachgezogen, es gibt keine Abweichung mehr. Die Gegenprobe der Migration (E17) prüft damit
  nur noch, dass die ankernormierten Werte (E2) exakt dasselbe ergeben wie `unit.c`.

**Cross-Community:** `pairing_ledger_anchor` bleibt öffentlich. OUTBOUND auf A und INBOUND
auf B tragen dasselbe `cross_community_cv`; der Node vergleicht nur Bytes — Betrag bleibt
verborgen.

---

## 6. Node-Änderungen (`../gradido_node`)

- `src/task/HieroMessageToTransactionTask.cpp` — Proof-Verifikation statt/zusätzlich zu
  `validate::Type::SINGLE`
- Neu: Nullifier-Set (LMDB, `src/model/files/LMDBWrapper`), Note-Commitment-Tree +
  Anchor-Root-Historie, beides pro Community
- Neu: Schöpfungsindex pro Community — Summe pro (Monatsadresse, Zielmonat) und
  Adresse → Zielmonat (E7). Auswertungen pro Kategorie und Projektbezug für die
  Plausibilitätsprüfung können auch außerhalb des Nodes laufen.
- Schöpfung: Node berechnet `u`, `rho` und `cm` selbst und hängt `cm` an den Note-Tree (E7)
- Neu: Genesis-Import — historische Tx aus dem Genesis-Paket einlesen, Proofs per Batch
  prüfen, historische Regeln für `LEGACY_GRADIDO_DB_*`-Anker; die erste Hiero-Tx setzt
  auf der Genesis auf (E17)
- Veröffentlichung aller Tx über den GradidoNode; Hiero nur Ordnung und vorerst Verteilung,
  später nur Hashes (E9)
- `NODE_TRIGGER_TRANSACTION_ID` als Anker-Typ entfällt mit den node-getriggerten Tx (E8)
- Neu: Moderatorenindex pro Community — Schlüssel → Aktivierungsintervalle in
  Chain-Reihenfolge, geprüft bei jeder Schöpfung (E16)
- `src/blockchain/FileBased` — Pruning-Pfad entlang der `coldData`-Naht (E11)
- Entfällt: `TransactionTriggerEvent`, `createTransactionByEvent`,
  `SimpleOrderingManager`-Triggerpfad für Timeouts (E8)
- `AddressIndex`, `PublicKeyDictionary`, `TransactionsIndex` nach Pubkey verlieren für
  abgeschirmte Tx ihre Bedeutung
- Bei eigenem Ledger: `confirmed_at`, 120s-Fenster und `running_hash` brauchen eine neue
  Ordnungsquelle — `OrderingManager`/`SimpleOrderingManager` sind der Ansatzpunkt.
  Das ist der teure Teil eines Ledger-Ersatzes, nicht der ZK-Teil.

---

## 7. Was öffentlich bleibt

Transaktionstyp, Zeitstempel, Community-ID, Cross-Group-Richtung, Anzahl Actions (→ padden).

Schöpfungen bleiben bewusst öffentlich (E7): Betrag, Zieldatum, Kategorie, Projektbezug,
Monatsadresse, Signierer, `memo_cm`. Daraus ablesbar — und gewollt für die
Plausibilitätsprüfung: Mitgliederzahl in der Größenordnung, Schöpfung pro Kategorie und
Projekt, bei Werken mit wenigen Beteiligten auch pro Person, und welcher Moderator was
unterzeichnet hat. Nicht ablesbar: was mit dem geschöpften Geld geschieht, welcher Status hinter einer
Status-Schöpfung steht, und (ohne Projektbezug) welche Monatsadressen demselben Menschen
gehören.

| Beobachter | bisheriges Format | danach |
|---|---|---|
| Öffentlichkeit / Hiero-Topic | alles | Typ, Zeit, Community; Schöpfungen (E7) |
| fremde Community + deren Node | alles bei Cross-Community | nichts über Beteiligte/Beträge von Transfers |
| Node-Betreiber, Blockdateien | alles | Schöpfungen, sonst nichts |
| eigene Community (verwahrte Nutzer) | alles | alles, bis Client-Proving (E5/E6) |

Die zweite Zeile rechtfertigt den Aufwand.

---

## 8. Offene Fragen

0. ~~Decay pro Action kaufmännisch runden (unit.c) oder abrunden?~~ **Entschieden:** bleibt
   wie unit.c. Bewusst in Kauf genommen: eine Note, die sehr oft an sich selbst geschickt
   wird, zerfällt durch die Rundung nicht (100 GDD alle 20 s, 1 GDD alle 38 min).

1. **N** in E10 (Note-Ablauf) — Vorschlag 5 Jahre; Trade-off Speicher gegen Kulanz.
2. Epochenlänge der Commitment-Trees (Jahr? Quartal?).
3. ~~Bleibt `RegisterAddress` öffentlich, oder Circuit C?~~ **Entfällt:** kein
   Empfängerregister mehr (E14).
4. ~~Zielmonat der Schöpfung öffentlich lassen oder verbergen?~~ **Entschieden:** Schöpfung
   öffentlich inkl. Kategorie, Projektbezug und Monatsadresse (E7).
5. Action-Padding: 2/2 unter Hedera, 4/4 bei eigenem Ledger — ab wann umstellen?
6. In-Browser-Proving für Selbstverwahrer: halo2/WASM liegt heute bei ~10–60 s für einen
   Orchard-großen Circuit → spricht für native App. Nicht auf delegiertes Proving mit
   Blinding setzen, das ist Forschung.
7. ~~Zielformat der DB-Migration~~ **Entschieden:** nicht transparent, sondern jede
   historische Tx im Zielformat mit Proof, veröffentlicht als Genesis über den GradidoNode,
   nicht über Hiero (E17). Verworfen: Stichtag-Salden (Geldmenge wäre nur Behauptung der
   Community, Nutzer könnten ihre Historie nicht ohne DB rekonstruieren).
8. Hedera-Nachrichtengröße: ~5 KB/Tx erfordert HCS-Chunking
   (`ConsensusMessageChunkInfo` existiert) und hebt die Gebühren um Faktor ~5–6. Betrifft
   nur neue Tx (Historie läuft nicht über Hiero, E17) und entfällt, sobald das Gossip im
   GradidoNode fertig ist und Hiero nur noch Hashes ordnet (E9).
9. ~~Widerruf eines Signierschlüssels~~ **Entschieden:** `ModeratorUpdate` mit
   `active = false`, signiert von `CommunityRoot` (E16).
10. Existenzrückfrage per Federation (E14) anbieten? Nützlich gegen gültige, aber verwaiste
    Adressen; die Empfänger-Community erfährt dabei, dass eine Zahlung ansteht.
11. ~~Feste Adresse pro Konto oder diversifizierte Adressen?~~ **Entschieden:**
    diversifizierte Adressen; Schöpfungsadressen wechseln monatlich (E7, E14).
12. Wer hält den Memo-Schlüssel (E15) — Community, Empfänger, beide? Mehrere Ciphertexte
    desselben Memos für verschiedene Schlüssel?
13. Memo-Verschlüsselung im Circuit beweisen (E15), zumindest für Schöpfungen? Macht
    Memo-Pflicht und Längenregeln beweisbar, kostet Rows proportional zur Memo-Länge.
14. ~~Schutz des `user_link`-Schlüssels auf der Chain~~ **Entfällt:** Der E-Mail-Hash bleibt
    Community-intern (E14).
15. Doppelmitgliedschaft bei Status-Schöpfungen (dieselbe Person in zwei Communities): nur
    durch die Communities selbst erkennbar — Abgleich per Federation oder bewusst offen?
16. ~~Signierer öffentlich oder privat?~~ **Entschieden:** öffentlich, Moderator per
    `ModeratorUpdate` (E16).
17. Name "Werk" **entschieden** (alles Vervielfältigbare). Offen bleibt die Abgrenzung:
    Wohin gehören ortsunabhängige, nicht vervielfältigbare Leistungen (Online-Beratung,
    Fernunterricht)? Sie lassen sich wie Werke in zwei Communities abrechnen, haben aber
    kein Projekt.
18. Projektbezug ist bei Werk **Pflicht** (entschieden). Offen: Format (URL, Projekt-ID aus
    einem gemeinsamen Verzeichnis?) und wer IDs über Communities hinweg vergibt, sodass
    dasselbe Projekt überall dieselbe Referenz hat.
19. Rotation und Kompromittierung des `CommunityRoot`-Schlüssels: einzige Quelle der
    Moderatoren-Berechtigung (E16), heute ohne Rotation. Eigener Tx-Typ oder Mehrfachsignatur?
20. Moderatoren-Befugnisse einschränken (z. B. nur bestimmte Kategorien)? Und sollen
    Schöpfungen für einen Moderator selbst von einem zweiten Moderator signiert werden
    müssen (Community-intern, öffentlich nicht prüfbar)?

---

## 9. Reihenfolge

0. **Die Chain startet direkt im Zielformat**, nicht transparent. Die ganze DB-Historie
   wird übersetzt und als Genesis über den GradidoNode veröffentlicht (E17); Hiero ordnet nur
   neue Tx (E9).
1. **Ankernormierte Werte ohne ZK** (E2) — `GradidoUnit` intern umstellen, klassisch testbar.
   Riskantester Refactor, deshalb zuerst.
   Parallel und ohne ZK:
   - **Adresskodierung** nach ZIP 316 in Wallet/Backend (E14)
   - **Kategorie und Projektbezug** der Schöpfung im DB-Backend erfassen — liefert sofort
     Daten für die Plausibilitätsprüfung und für die Migration (E7); Kategorie darf vorerst
     leer bleiben
2. **Note-Tree + Nullifier-Set im Node**, Shadow-Mode gegen die DB-Salden auf migrierten
   Testdaten.
3. **Circuit A (Transfer)** ohne Register, mit `memo_cm` (E15) und diversifizierten Adressen.
4. **Öffentliche Schöpfung als Note** (E7) und **`ModeratorUpdate`** (E16): Monatsadressen,
   Summenprüfung pro Adresse, Node rechnet `cm` — kein Circuit.
5. **E8** Deferred auf Zeitschloss, node-getriggerte Tx entfernen.
6. **Migration als Vollständigkeitstest** (E17): jede historische Tx übersetzen und beweisen,
   Salden centgenau gegen die DB prüfen, Lücken im Format schließen. Beliebig oft
   wiederholen (erster Stand zum Vorführen, Kategorien ergänzen, neu migrieren). Letzter
   Lauf: Genesis-Paket im GradidoNode veröffentlichen; die erste Hiero-Tx setzt darauf auf →
   **Start**.
7. **E10/E11** Pruning und Note-Ablauf scharfschalten.
8. **E13** rekursiver Zustandsbeweis — Genesis und Neu-Sync mit einem Beweis.
