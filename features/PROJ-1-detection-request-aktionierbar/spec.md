# PROJ-1: Detection Requests aktionierbar machen

**Status:** Planned
**Created:** 2026-11-20

## Requirements
- Keine

## User Stories
- Als Analyst möchte ich einem Detection Request einen kurzen Titel und eine ausführliche Beschreibung geben, damit das Detection-Engineering-Team versteht, was erkannt werden soll und warum.
- Als Analyst möchte ich den Implementierungsstatus eines Detection Requests pflegen, damit sichtbar ist, was offen, in Arbeit oder erledigt ist.
- Als Analyst möchte ich den Status auch nach Abschluss des Interviews und direkt in der Systemansicht ändern, damit ich dem Fortschritt folgen kann, ohne das Interview zu öffnen.
- Als Analyst möchte ich bei „Umgesetzt“ die Regel oder den Use Case verknüpfen, damit nachvollziehbar ist, womit der Request umgesetzt wurde.
- Als Analyst möchte ich bei einem Re-Interview alle bisherigen Requests samt Status übernehmen, damit nichts verloren geht und der Stand klar erkennbar ist.

## Out of Scope
- Statushistorie (nur der letzte Stand wird gespeichert; eine Historie wäre ein eigenes Feature).
- Markdown oder sonstige Formatierung in der Beschreibung (nur Freitext mit Zeilenumbrüchen).
- Automatische Berechnung der Risikoabdeckung aus dem Request-Status. Die Abdeckung wird weiter über Use Cases und Regeln berechnet.
- Zusätzliche Statuswerte wie „Wartet auf Logquelle“.
- Zuweisung an Personen, Fälligkeitsdaten, Priorität.
- Kommentare oder Diskussionen pro Request.

## Acceptance Criteria

### Titel und Beschreibung
- [ ] AK-1: Angenommen ein Interview im Entwurf, wenn der Analyst einen Request mit Titel, Bedrohung und optionaler Beschreibung anlegt, dann wird er mit Status „Offen“ gespeichert und in der Liste mit Titel und Status-Chip angezeigt.
- [ ] AK-2: Angenommen das Formular für einen neuen Request, wenn der Titel leer ist oder nur aus Leerzeichen besteht, dann lässt sich der Request nicht speichern.
- [ ] AK-3: Angenommen das Formular, wenn der Titel länger als 200 oder die Beschreibung länger als 10.000 Zeichen ist, dann wird das Speichern mit einer Fehlermeldung abgelehnt.
- [ ] AK-4: Angenommen ein Request mit mehrzeiliger Beschreibung, wenn der Analyst ihn aufklappt, dann wird die Beschreibung mit erhaltenen Zeilenumbrüchen als reiner Text angezeigt (ohne Markdown-Interpretation).
- [ ] AK-5: Angenommen ein Interview im Entwurf, wenn der Analyst Titel, Beschreibung oder Bedrohung eines Requests ändert, dann wird dies gespeichert und Status, Statusnotiz und Verknüpfung bleiben unverändert.
- [ ] AK-6: Angenommen ein abgeschlossenes Interview, wenn der Analyst die Requests ansieht, dann sind Titel, Beschreibung und Bedrohung nicht bearbeitbar.

### Status
- [ ] AK-7: Angenommen ein Request, wenn der Analyst den Status wählt, dann stehen genau diese Werte zur Verfügung: Offen, In Bearbeitung, Umgesetzt, Abgelehnt, Nicht umsetzbar; Wechsel zwischen allen Werten sind erlaubt.
- [ ] AK-8: Angenommen ein Request, wenn der Status auf „Abgelehnt“ oder „Nicht umsetzbar“ gesetzt wird und die Statusnotiz leer ist, dann wird das Speichern abgelehnt und eine Begründung verlangt.
- [ ] AK-9: Angenommen ein Request, wenn der Status auf „Offen“, „In Bearbeitung“ oder „Umgesetzt“ gesetzt wird, dann ist die Statusnotiz optional.
- [ ] AK-10: Angenommen ein Request mit dem Status „Umgesetzt“, wenn der Analyst optional eine L3-Regel oder einen L2-Use-Case verknüpft, dann wird die Verknüpfung gespeichert und beim Request angezeigt.
- [ ] AK-11: Angenommen ein gespeicherter Statuswechsel, wenn die Seite neu geladen wird, dann zeigt der Request Status, Notiz, Verknüpfung sowie „zuletzt geändert von X am Y“.
- [ ] AK-12: Angenommen ein abgeschlossenes Interview, wenn der Analyst den Status eines Requests ändert, dann wird die Änderung gespeichert, ohne dass der eingefrorene Interview-Inhalt (Titel, Beschreibung, Bedrohung) sich ändert.
- [ ] AK-13: Angenommen ein Benutzer ohne Schreibrecht auf das System, wenn er einen Status ändern will, dann wird dies abgelehnt (gleiche Rechte wie beim Bearbeiten von Interviews).
- [ ] AK-14: Angenommen Requests, die vor diesem Feature angelegt wurden, wenn das Feature aktiv wird, dann haben sie den Status „Offen“, ihren bisherigen Text als Beschreibung und die erste Zeile (auf 200 Zeichen gekürzt) als Titel; ist der alte Text kürzer als 200 Zeichen und einzeilig, ist er der Titel und die Beschreibung bleibt leer.

### Anzeige
- [ ] AK-15: Angenommen die Interview-Seite, wenn Requests vorhanden sind, dann zeigt jeder Request einen deutlich erkennbaren Status-Chip, in Entwurf und im abgeschlossenen Interview.
- [ ] AK-16: Angenommen die Systemdetail-Seite, wenn sie geöffnet wird, dann listet „Detection requests“ standardmäßig nur Requests mit „Offen“ und „In Bearbeitung“, jeweils mit Titel, Status-Chip, Bedrohung und Zugang zur Beschreibung.
- [ ] AK-17: Angenommen die Systemdetail-Seite, wenn der Analyst den Statusfilter ändert, dann werden Requests der gewählten Status angezeigt (Mehrfachauswahl, alle fünf Werte wählbar).
- [ ] AK-18: Angenommen die Systemdetail-Seite, wenn der Analyst bei einem Request den Status ändert, dann wird er dort gespeichert, ohne dass das Interview geöffnet werden muss.
- [ ] AK-19: Angenommen die Risikoabdeckung, wenn ein Risiko Requests hat, dann zeigt das Chip „Detection request“ zusätzlich den Status; der Abdeckungsstatus des Risikos ändert sich dadurch nicht.
- [ ] AK-20: Angenommen der Interview-Report-Export, wenn er erzeugt wird, dann enthält er pro Request Titel, Beschreibung, Bedrohung und den Status zum Zeitpunkt des Exports.

### Löschen und Entfernen von Bedrohungen
- [ ] AK-21: Angenommen ein Request mit Status „Offen“ im Entwurf, wenn die zugehörige Bedrohung oder Komponente entfernt wird, dann wird der Request nach der bekannten Rückfrage (mit Anzahl) mitgelöscht.
- [ ] AK-22: Angenommen ein Request mit einem anderen Status als „Offen“, wenn die zugehörige Bedrohung oder Komponente entfernt werden soll, dann wird das blockiert und die betroffenen Requests werden namentlich genannt.
- [ ] AK-23: Angenommen ein Request mit einem anderen Status als „Offen“ im Entwurf, wenn der Analyst ihn löscht, dann ist vorher eine Bestätigung nötig.
- [ ] AK-24: Angenommen ein abgeschlossenes Interview, wenn der Analyst Requests ansieht, dann gibt es keine Löschfunktion.

### Re-Interview
- [ ] AK-25: Angenommen ein abgeschlossenes Interview mit Requests aller Status, wenn ein Re-Interview gestartet wird, dann werden alle Requests unabhängig vom Status mit Titel, Beschreibung, Bedrohung, Status, Notiz und Verknüpfung ins neue Entwurfs-Interview übernommen.
- [ ] AK-26: Angenommen ein übernommener Request, wenn der Status im neuen Entwurf oder in der Systemansicht geändert wird, dann gilt die Änderung für den Request insgesamt: Es gibt pro Request einen Status, und in der Systemansicht erscheint er nur einmal.
- [ ] AK-27: Angenommen das neue Re-Interview, wenn übernommene Requests angezeigt werden, dann ist ihr Status deutlich sichtbar (Status-Chip); Requests mit „Umgesetzt“, „Abgelehnt“ oder „Nicht umsetzbar“ sind von offenen visuell klar unterscheidbar.
- [ ] AK-28: Angenommen ein Re-Interview, wenn die Bedrohung eines übernommenen Requests im Entwurf entfällt, dann gelten dieselben Regeln wie in AK-21 und AK-22.

### Gleichzeitigkeit
- [ ] AK-29: Angenommen zwei Analysten ändern gleichzeitig den Status desselben Requests, wenn beide speichern, dann gilt der zuletzt gespeicherte Stand und der andere Analyst sieht nach dem Neuladen „zuletzt geändert von X am Y“.
- [ ] AK-30: Angenommen ein Entwurf, der mit einem älteren Stand geöffnet wurde, wenn zwischenzeitlich ein Status gesetzt wurde und der Entwurf gespeichert wird, dann bleibt der zwischenzeitlich gesetzte Status erhalten.

### Leere Zustände
- [ ] AK-31: Angenommen ein System ohne Requests oder ein Statusfilter ohne Treffer, wenn die Liste angezeigt wird, dann erscheint ein Leerzustandstext statt einer leeren Fläche.

## Edge Cases
- EC-1: Status „Umgesetzt“ ohne Verknüpfung: erlaubt, die Verknüpfung ist optional.
- EC-2: Die verknüpfte L3-Regel oder der L2-Use-Case wird später gelöscht: der Request zeigt die Verknüpfung als „gelöscht“ an, Status und Notiz bleiben erhalten.
- EC-3: Statuswechsel auf „Offen“ nach „Abgelehnt“: die alte Begründung bleibt als Notiz stehen und kann bearbeitet werden.
- EC-4: Statuswechsel schlägt fehl (Netzwerk, Server): der Status springt in der Oberfläche zurück und es erscheint eine Fehlermeldung.
- EC-5: Statusnotiz überschreitet die Maximallänge: Speichern wird mit Fehlermeldung abgelehnt.
- EC-6: Beschreibung enthält HTML oder Skript-Zeichen: wird als reiner Text angezeigt und nie interpretiert.
- EC-7: Zwei Requests mit identischem Titel an derselben Bedrohung: erlaubt.
- EC-8: Ein Request in einem Re-Interview wird im neuen Entwurf gelöscht, obwohl er Status „Offen“ hat: er verschwindet nur aus dem neuen Interview und bleibt im alten abgeschlossenen Interview erhalten.

## Technical Requirements
- Bestehende Requests werden verlustfrei migriert (AK-14); der Interview-Report und die eingefrorenen Ergebnisse abgeschlossener Interviews bleiben lesbar.
- Eine Statusänderung muss auf abgeschlossenen Interviews möglich sein, ohne deren eingefrorenen Inhalt zu verändern.
- Texte der Oberfläche liegen in den bestehenden Sprachen (de, nl, en).

## Open Questions
- [x] Blockade aus AK-22 auch für übernommene „Abgelehnt“/„Nicht umsetzbar“-Requests im Re-Interview? Entschieden: ja, wie im Entwurf (AK-28).
- [x] Maximallänge der Statusnotiz: 2.000 Zeichen.
- [x] Rolle für Statusänderungen: dieselben Rechte wie beim Bearbeiten von Interviews (Admin und Analyst).

## Product Decisions
- Status ist nach Abschluss änderbar, der übrige Inhalt eingefroren: Requests werden meist erst nach dem Interview umgesetzt (2026-11-20).
- Fünf Statuswerte, Begründung bei „Abgelehnt“ und „Nicht umsetzbar“ Pflicht: nachvollziehbare Ablehnung ohne Statusflut (2026-11-20).
- Titel und Beschreibung statt eines Felds: Listen bleiben kompakt, Details sind abrufbar (2026-11-20).
- Nur der letzte Stand, keine Historie: Aufwand gering, Historie bei Bedarf eigenes Feature (2026-11-20).
- Status auf Interview- und Systemseite änderbar, Standardfilter „Offen“ und „In Bearbeitung“: Die Systemseite soll als Aufgabenliste taugen (2026-11-20).
- Löschschutz für Requests mit Status ≠ „Offen“: Bearbeitete Arbeit darf nicht stillschweigend verloren gehen (2026-11-20).
- Status-Änderung nach Last-write-wins, unabhängig vom Interview-Versions-Lock: Statuswechsel sind klein und betreffen nur einen Request (2026-11-20).
- Re-Interview übernimmt alle Requests unabhängig vom Status, Status deutlich sichtbar: auf Wunsch des Nutzers, damit der Gesamtstand sichtbar bleibt (2026-11-20).
- Ein Request hat einen gemeinsamen Status über Interviews hinweg: keine doppelte Pflege, keine Duplikate in der Systemansicht (2026-11-20).
- Offene Fragen am 2026-11-20 wie vorgeschlagen entschieden: Blockade gilt auch im Re-Interview, Notiz max. 2.000 Zeichen, Rechte wie beim Bearbeiten von Interviews (2026-11-20).
- Als Lücke zählen nur Requests mit Status „Offen“ und „In Bearbeitung“: Umgesetzte oder abgelehnte Requests sind erledigt und dürfen die Lückenzahl des Systems nicht erhöhen. Umsetzung-Entscheidung, nicht im Interview besprochen, bitte prüfen (2026-11-20).
