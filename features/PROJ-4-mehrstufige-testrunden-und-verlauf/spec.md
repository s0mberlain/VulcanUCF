# PROJ-4: Mehrstufige Testrunden und Verlauf (Purple Teaming)

**Status:** Planned
**Created:** 2026-11-22

## Zusammenfassung

Tests aus PROJ-3 haben heute genau eine Ausführung und ein Ergebnis. Beim Purple Teaming läuft ein Test aber interaktiv und in mehreren Runden: Das Red Team führt aus, das Blue Team prüft die Erkennung, die Regel wird angepasst, das Red Team führt erneut aus. Diese Spec bildet das ab:

- Ein Test besteht aus **Runden**. Jede Runde hat einen Red-Team-Teil (Ausführung) und einen Blue-Team-Teil (Ergebnis).
- Beide Seiten schreiben **Kommentare**, die zusammen mit automatischen Einträgen als **Verlauf** am Test stehen.
- Die Detailansicht eines Tests ist an **VECTR** orientiert: zwei Spalten für Red und Blue je Runde, darunter der Verlauf.
- Verifikation, Scope-Abdeckung und Erkennungslücken richten sich nach der **jüngsten abgeschlossenen Runde mit Ergebnis**.
- Pro Kampagne legt die Einstellung **Zusammenarbeit** fest, ob das Red Team Blue-Team-Inhalte sofort sieht („Offen“, Purple Team) oder erst nach Abschluss („Verdeckt“, wie bisher).

## Requirements

- PROJ-3 (Use-Case-Verifikation durch Tests): Kampagnen, Tests, Quick Tests, Red-Team-Rolle, Verifikation mit Scopes, Erkennungslücken und Anhänge müssen vorhanden sein. PROJ-4 ändert deren Verhalten an den genannten Stellen.

## Begriffe

| Begriff | Bedeutung |
|---|---|
| Runde | Ein Versuch eines Tests („Runde 1, Runde 2 …“) mit Red-Team-Teil, Blue-Team-Teil und Anhängen. |
| Rundenstatus | Offen (nicht ausgeführt), Wartet auf Blue (ausgeführt, kein Ergebnis), Abgeschlossen (Ergebnis eingetragen oder „Nicht ausführbar“). |
| Red-Team-Teil einer Runde | Ausführungsstatus (Nicht ausgeführt, Ausgeführt, Nicht ausführbar), Startzeit, Endzeit (optional), „Was wurde ausgeführt“ (Variante oder angepasstes Vorgehen), Notizen. |
| Blue-Team-Teil einer Runde | Ergebnis (Blocked, Alerted, Logged, Not detected), Zeitpunkt der Erkennung, „Erkannt durch“ (Auswahl aus der Referenzliste „Detection technologies“, null oder mehrere, optional), Notizen. |
| Aktuelles Ergebnis | Das Ergebnis der jüngsten Runde mit Ergebnis. Es zählt für Verifikation, Scope-Abdeckung und Lücken. |
| Verlauf | Zeitleiste am Test mit Kommentaren beider Seiten und automatischen Einträgen. |
| Zusammenarbeit | Einstellung je Kampagne: „Verdeckt“ (Standard) oder „Offen (Purple Team)“. |

## Rollen und Rechte

| Rolle | Rechte |
|---|---|
| Admin | alles wie Analyst; entfernt Kommentare; ändert „Zusammenarbeit“ |
| Analyst (Blue Team) | eröffnet Runden, trägt Blue-Team-Teil ein, schreibt Kommentare, ändert „Zusammenarbeit“ |
| Auditor | liest alles, schreibt nichts |
| Red team | eröffnet Runden in zugewiesenen Kampagnen, trägt den Red-Team-Teil ein, schreibt Kommentare; sieht Blue-Team-Inhalte nach der Einstellung „Zusammenarbeit“ |

## User Stories

- Als Red-Teamer möchte ich mehrere Runden eines Tests ausführen und je Runde eintragen, was genau ausgeführt wurde, damit das Blue Team die Versuche unterscheiden kann.
- Als Analyst möchte ich je Runde das Ergebnis und die Erkennungsquelle eintragen, damit sichtbar wird, wie sich die Erkennung nach Anpassungen verbessert.
- Als Red-Teamer und als Analyst möchte ich Kommentare an einem Test schreiben und im Verlauf lesen, damit wir uns live abstimmen und die Abstimmung nachvollziehbar bleibt.
- Als Analyst möchte ich pro Kampagne wählen, ob das Red Team Blue-Team-Inhalte sofort sieht, damit ich Purple-Team-Termine und Blind-Tests unterstützen kann.
- Als Analyst möchte ich, dass die Verifikation und die Lücken aus der jüngsten abgeschlossenen Runde folgen, damit eine behobene Lücke nach einer erfolgreichen Folgerunde schließt.
- Als Auditor möchte ich den gesamten Verlauf eines Tests lesen, damit ich die Entscheidungen nachvollziehen kann.

## Out of Scope

- Benachrichtigungen (E-Mail oder Hinweise außerhalb der Seite) und Markierung neuer Einträge seit dem letzten Besuch.
- Bearbeiten oder Löschen von Kommentaren durch ihre Autoren (nur Admins entfernen Kommentare).
- Anhänge an Kommentaren (Dateien hängen an der Runde).
- Gleichzeitig laufende Runden eines Tests; Löschen von Runden mit Einträgen.
- Mehr als 20 Runden je Test.
- Echtzeit-Aktualisierung der Ansicht (Aktualisierung beim Laden und Speichern genügt).
- Vorlagen mit mehreren Runden; die Testbibliothek bleibt unverändert.
- Neue Berichte über Runden (Verbesserungsverlauf der Erkennung über mehrere Tests, Auswertung der Anzahl Runden).

## Acceptance Criteria

### Runden
- [ ] AK-1: Angenommen ein neuer Test, wenn er angelegt wird, dann hat er genau eine Runde („Runde 1“) im Status „Offen“.
- [ ] AK-2: Angenommen ein bestehender Test aus PROJ-3 mit Ausführung und Ergebnis, wenn PROJ-4 ausgeliefert ist, dann hat er genau eine Runde mit denselben Werten, Notizen und Anhängen, und Verifikation und Lücken bleiben unverändert.
- [ ] AK-3: Angenommen die jüngste Runde eines Tests ist abgeschlossen (Ergebnis eingetragen oder „Nicht ausführbar“) und die Kampagne läuft, wenn ein Analyst oder zugewiesener Red-Teamer „Neue Runde“ wählt, dann entsteht die nächste Runde im Status „Offen“, und der Verlauf nennt, wer sie eröffnet hat.
- [ ] AK-4: Angenommen die jüngste Runde ist noch nicht abgeschlossen, wenn jemand „Neue Runde“ wählt, dann ist das nicht möglich und die Oberfläche zeigt „Runde n ist noch offen“.
- [ ] AK-5: Angenommen die neue Runde, wenn sie eröffnet wird, dann ist „Was wurde ausgeführt“ mit dem Wert der Vorrunde vorbelegt, Status, Zeiten, Ergebnis und Notizen sind leer.
- [ ] AK-6: Angenommen ein Test mit 20 Runden, wenn jemand eine weitere eröffnen will, dann ist das nicht möglich, und die Meldung nennt die Obergrenze.
- [ ] AK-7: Angenommen eine Runde ohne jeden Eintrag, wenn ihr Eröffner sie löscht, dann verschwindet sie; eine Runde mit Eintrag (Ausführung, Ergebnis, Datei oder Kommentar zur Runde) lässt sich nicht löschen.
- [ ] AK-8: Angenommen eine Kampagne im Status „Geplant“ oder „Abgeschlossen“, wenn jemand eine Runde eröffnen oder einen Teil einer Runde ändern will, dann ist das gesperrt; ein Analyst kann die Kampagne wieder öffnen.
- [ ] AK-9: Angenommen die Startzeit der Ausführung einer Runde liegt vor der Startzeit der Vorrunde, wenn gespeichert wird, dann erscheint eine Fehlermeldung am Feld und nichts wird gespeichert.

### Red-Team-Teil
- [ ] AK-10: Angenommen eine offene Runde in einer laufenden Kampagne, wenn der Red-Teamer (oder ein Analyst) Ausführungsstatus, Startzeit, optional Endzeit, „Was wurde ausgeführt“ und Notizen speichert, dann stehen sie in der Spalte „Red Team“ der Runde mit Person und Zeitpunkt.
- [ ] AK-11: Angenommen der Ausführungsstatus „Ausgeführt“, wenn die Startzeit fehlt, dann wird nicht gespeichert und das Feld nennt „Pflichtfeld“.
- [ ] AK-12: Angenommen die Endzeit liegt vor der Startzeit, wenn gespeichert wird, dann erscheint eine Fehlermeldung am Feld.
- [ ] AK-13: Angenommen ein Red-Teamer, wenn er die Spalte „Blue Team“ einer Runde ändern will, dann ist das nicht möglich; ein Analyst kann den Red-Team-Teil nur als Vertretung ändern, und der Verlauf nennt ihn als Person.

### Blue-Team-Teil
- [ ] AK-14: Angenommen eine ausgeführte Runde, wenn der Analyst Ergebnis (vier farbige Auswahlfelder), Zeitpunkt der Erkennung, „Erkannt durch“ (Einträge der Referenzliste „Detection technologies“) und Notizen speichert, dann erscheinen sie in der Spalte „Blue Team“; die Time to detect (Erkennung minus Startzeit) steht bei Blocked und Alerted.
- [ ] AK-15: Angenommen eine Runde, die nicht „Ausgeführt“ ist, wenn der Analyst ein Ergebnis eintragen will, dann ist das nicht möglich.
- [ ] AK-16: Angenommen der Zeitpunkt der Erkennung liegt vor der Startzeit der Runde, wenn gespeichert wird, dann erscheint eine Fehlermeldung am Feld.
- [ ] AK-14a: Angenommen die Auswahl „Erkannt durch“, wenn der Analyst einen Eintrag wählt, dann stammen die Einträge aus der Referenzliste „Detection technologies“; fehlt ein Eintrag, kann er dort neu angelegt und gewählt werden (wie bei Logquellen), ein frei getippter Name außerhalb der Liste wird nicht gespeichert.
- [ ] AK-14b: Angenommen eine Runde mit „Erkannt durch“, wenn sie angezeigt wird, dann ist jede Erkennung ein Link, der die Use-Case-Ansicht nach dieser Detection technology filtert (wie die Verweise der Referenzlisten); wird ein Eintrag der Referenzliste umbenannt, zeigt die Runde den neuen Namen.
- [ ] AK-14c: Angenommen ein Eintrag der Referenzliste, der in Runden verwendet wird, wenn er gelöscht werden soll, dann nennt die Meldung die Verwendung (Zahl der Runden); die Runden behalten den Namen als nicht mehr verlinkten Text.
- [ ] AK-17: Angenommen ein bereits eingetragenes Ergebnis, wenn der Analyst es ändert, dann steht im Verlauf „Ergebnis von X zu Y geändert“ mit Person und Zeit, und Verifikation und Lücken werden neu berechnet.

### Aktuelles Ergebnis, Verifikation und Lücken
- [ ] AK-18: Angenommen ein Test mit mehreren Runden, wenn sein aktuelles Ergebnis bestimmt wird, dann ist es das Ergebnis der jüngsten Runde mit Ergebnis; eine neue, noch offene Runde ändert es nicht.
- [ ] AK-19: Angenommen Runde 1 „Not detected“ und danach Runde 2 „Alerted“ auf derselben Regel und denselben Scopes, wenn das Ergebnis von Runde 2 gespeichert wird, dann schließt die Lücke aus Runde 1, und die Regel gilt für die abgedeckten Scopes als erfolgreich getestet (Datum: Startzeit von Runde 2).
- [ ] AK-20: Angenommen Runde 1 „Alerted“ und danach Runde 2 „Logged“, wenn das Ergebnis von Runde 2 gespeichert wird, dann öffnet eine Lücke, und die Verifikation aus Runde 1 entfällt für diese Scopes.
- [ ] AK-21: Angenommen eine akzeptierte Lücke, wenn eine neue Runde mit einem Fehlergebnis folgt, dann öffnet eine neue Lücke; die Akzeptanz gilt nur für das Ergebnis, für das sie gegeben wurde.
- [ ] AK-22: Angenommen eine Kampagne, wenn sie abgeschlossen werden soll, dann müssen alle Tests in der jüngsten Runde abgeschlossen sein (Ergebnis oder „Nicht ausführbar“); sonst nennt der Dialog die offenen Tests mit ihrer Runde.
- [ ] AK-23: Angenommen die Liste der Tests einer Kampagne, wenn sie angezeigt wird, dann zeigt jede Zeile den Teststatus (Offen, Wartet auf Blue, Abgeschlossen), das aktuelle Ergebnis und die Zahl der Runden; der Filter „Nicht abgeschlossen“ nennt Tests mit offener jüngster Runde.

### Kommentare und Verlauf
- [ ] AK-24: Angenommen eine laufende Kampagne, wenn ein Analyst, Admin oder zugewiesener Red-Teamer einen Kommentar schreibt (Markdown, nicht leer, höchstens 10.000 Zeichen), dann erscheint er im Verlauf mit Person, Seite (Red oder Blue), Zeit und der gewählten Runde.
- [ ] AK-25: Angenommen ein Auditor, wenn er den Verlauf ansieht, dann kann er lesen, aber kein Kommentarfeld bedienen.
- [ ] AK-26: Angenommen eine Kampagne im Status „Geplant“ oder „Abgeschlossen“, wenn jemand kommentieren will, dann ist das nicht möglich, der Verlauf ist lesbar.
- [ ] AK-27: Angenommen ein Quick Test, wenn ein Analyst oder Admin kommentiert, dann geht das jederzeit; Quick Tests haben ebenfalls Runden und einen Verlauf.
- [ ] AK-28: Angenommen ein Kommentar, wenn sein Autor ihn bearbeiten oder löschen will, dann gibt es dafür keine Möglichkeit; ein Admin kann ihn entfernen, dann steht im Verlauf „Kommentar entfernt von Admin am …“ ohne den Text, und das Audit-Log nennt die Aktion.
- [ ] AK-29: Angenommen der Verlauf, wenn er angezeigt wird, dann enthält er neben den Kommentaren automatische Einträge in zeitlicher Reihenfolge: Runde eröffnet, Ausführung eingetragen oder geändert, Ergebnis eingetragen oder geändert (mit altem und neuem Wert), Datei angehängt oder entfernt, Kampagnenstatus geändert, „Zusammenarbeit“ geändert.
- [ ] AK-30: Angenommen ein Kommentar mit Markdown, wenn er angezeigt wird, dann ist er gerendert und bereinigt (kein Skript wird ausgeführt).

### Zusammenarbeit
- [ ] AK-31: Angenommen eine neue Kampagne, wenn sie angelegt wird, dann ist „Zusammenarbeit“ auf „Verdeckt“ gestellt.
- [ ] AK-32: Angenommen „Verdeckt“, wenn ein zugewiesener Red-Teamer einen Test ansieht, dann sieht er in den Runden weder Ergebnis, Erkennungszeit, „Erkannt durch“, Blue-Notizen, Blue-Anhänge noch Blue-Kommentare noch automatische Einträge zu Ergebnissen; er sieht Red-Einträge und alle Red-Kommentare; auch Schnittstellen liefern die Blue-Inhalte nicht aus.
- [ ] AK-33: Angenommen „Offen (Purple Team)“, wenn ein Red-Teamer einen Test ansieht, dann sieht er alle Inhalte der Blue-Seite sofort.
- [ ] AK-34: Angenommen ein Analyst oder Admin, wenn er „Zusammenarbeit“ in einer geplanten oder laufenden Kampagne ändert, dann gilt der Wert ab sofort, bisherige Inhalte werden entsprechend sichtbar oder wieder verdeckt, und die Änderung steht im Verlauf der Tests und im Audit-Log.
- [ ] AK-34a: Angenommen der Wechsel von „Offen“ auf „Verdeckt“, wenn der Analyst ihn wählt, dann erscheint ein Bestätigungsdialog mit dem Hinweis, dass das Red Team bereits Gesehenes nicht zurückgeben kann; ohne Bestätigung bleibt der Wert „Offen“. Der Wechsel von „Verdeckt“ auf „Offen“ nennt im Dialog, dass das Red Team ab sofort alle Blue-Inhalte sieht.
- [ ] AK-35: Angenommen eine abgeschlossene Kampagne, wenn ein Red-Teamer sie ansieht, dann sieht er alle Blue-Inhalte unabhängig von der Einstellung (nur lesend).
- [ ] AK-36: Angenommen ein Blue-Kommentar in „Verdeckt“, wenn die Kampagne abgeschlossen wird, dann ist er für das Red Team sichtbar.
- [ ] AK-37: Angenommen die Kampagnenliste in „Verdeckt“, wenn ein Red-Teamer sie ansieht, dann zeigt sie keine Ergebniszahlen, in „Offen“ zeigt sie die Zahlen.

### Layout der Detailansicht
- [ ] AK-38: Angenommen die Liste der Tests einer Kampagne oder der Quick Tests, wenn jemand einen Test wählt, dann öffnet sich die Detailansicht mit Kopf (Titel, Technik, verknüpfte Regeln mit Scopes, aktuelles Ergebnis, Kampagnenstatus), einer Leiste der Runden (Nummer, Ergebnisfarbe, „Neue Runde“), den zwei Spalten „Red Team“ und „Blue Team“ der gewählten Runde und darunter dem Verlauf.
- [ ] AK-39: Angenommen die Detailansicht, wenn die Rundenleiste bedient wird, dann wechselt der Inhalt der zwei Spalten auf die gewählte Runde, und der Verlauf zeigt weiter alle Runden mit der Rundennummer an den Einträgen.
- [ ] AK-40: Angenommen die Detailansicht, wenn sie geladen wird, dann ist die jüngste Runde gewählt und die Definition des Tests (Beschreibung, Vorgehen, Werkzeuge, Voraussetzungen) als eingeklappter Bereich erreichbar.
- [ ] AK-41: Angenommen eine Spalte der gewählten Runde, wenn ihr Teil gespeichert werden soll, dann hat jede Spalte ein eigenes „Speichern“; der Red-Teamer sieht die Blue-Spalte nur lesend oder gar nicht (nach „Zusammenarbeit“).
- [ ] AK-42: Angenommen eine schmale Anzeige (Telefonbreite), wenn die Detailansicht geöffnet ist, dann stehen die zwei Spalten untereinander, ohne waagerechtes Scrollen der Seite.
- [ ] AK-43: Angenommen die Detailansicht mit Tastatur, wenn die Rundenleiste, die Ergebnisauswahl und das Kommentarfeld bedient werden, dann sind sie erreichbar, mit sichtbarem Fokus und Namen für Screenreader.

### Anhänge, Nachvollziehbarkeit und gleichzeitige Bearbeitung
- [ ] AK-44: Angenommen Anhänge an einer Runde, wenn sie hochgeladen werden, dann gehören sie zur gewählten Runde und Seite (Red oder Blue) und folgen den Grenzen und Sichtbarkeitsregeln aus PROJ-3 und der Einstellung „Zusammenarbeit“.
- [ ] AK-45: Angenommen jede Aktion dieser Spec (Runde eröffnen oder löschen, Teil speichern, Kommentar schreiben oder entfernen, Zusammenarbeit ändern), wenn sie ausgeführt wird, dann steht sie mit Person und Zeitpunkt im Audit-Log.
- [ ] AK-46: Angenommen zwei Personen speichern denselben Teil derselben Runde, wenn die zweite speichert, dann erscheint „Diese Runde wurde von X geändert, bitte neu laden“ und ihre Eingaben werden zur Wiederherstellung angeboten; der Red-Team-Teil und der Blue-Team-Teil einer Runde überschreiben sich nicht gegenseitig.
- [ ] AK-47: Angenommen gleichzeitig geschriebene Kommentare, wenn beide gespeichert werden, dann erscheinen beide im Verlauf, nach Zeitpunkt des Speicherns geordnet.

## Edge Cases

- EC-1: Was passiert, wenn die jüngste Runde „Nicht ausführbar“ ist und eine neue Runde folgt? Das ist erlaubt (AK-3). Das aktuelle Ergebnis bleibt das der jüngsten Runde mit Ergebnis.
- EC-2: Was passiert, wenn noch keine Runde ein Ergebnis hat? Der Test hat kein aktuelles Ergebnis, keine Verifikation und keine Lücke; der Teststatus ist „Offen“ oder „Wartet auf Blue“.
- EC-3: Was passiert, wenn die Kampagne wieder geöffnet wird? Runden und Verlauf bleiben, der Verlauf zeigt „Kampagne wieder geöffnet“, Runden lassen sich wieder eröffnen.
- EC-4: Was passiert, wenn ein Red-Teamer nach Beginn von der Kampagne entfernt wird? Er sieht sie nicht mehr; seine Runden, Einträge und Kommentare bleiben mit seinem Namen im Verlauf.
- EC-5: Was passiert, wenn die verknüpfte Regel gelöscht wird? Der Verlauf bleibt vollständig, die Runden behalten ihre Ergebnisse, Verifikation und Lücken dieser Regel entfallen wie in PROJ-3.
- EC-6: Was passiert, wenn „Zusammenarbeit“ von „Offen“ auf „Verdeckt“ gestellt wird, während der Red-Teamer eine Seite offen hat? Die nächste Anfrage liefert die verdeckte Sicht, die Anzeige aktualisiert sich beim Speichern oder Neuladen; bereits gesehene Inhalte lassen sich nicht zurückholen (Hinweis im Dialog).
- EC-7: Was passiert bei sehr langem Verlauf (über 200 Einträge)? Die Ansicht lädt die jüngsten Einträge und bietet „Ältere anzeigen“; Kommentieren bleibt möglich.
- EC-8: Was passiert, wenn ein Kommentar leer oder zu lang ist? Er wird nicht gespeichert, das Feld nennt den Grund, der Text bleibt erhalten.
- EC-9: Was passiert, wenn das Speichern fehlschlägt (Netzwerk)? Eingaben und Kommentartext bleiben im Formular, die Meldung nennt das Problem, ein erneutes Speichern ist möglich.
- EC-10: Was passiert bei einem Quick Test? Alle Regeln dieser Spec gelten mit dem einen Unterschied, dass es keine Kampagne und kein Red-Team-Konto gibt; Analyst und Admin tragen beide Seiten ein, und „Zusammenarbeit“ entfällt.

## Technical Requirements

- Sichtbarkeit von Blue-Team-Daten und Blue-Kommentaren für Red-Teamer wird serverseitig durchgesetzt, nicht nur ausgeblendet (auch in Schnittstellen-Antworten und Verlauf).
- Kommentare und Notizen werden als Markdown bereinigt dargestellt; Eingaben des Red Teams werden nie als Markup ausgeführt.
- Die Migration bestehender Tests (eine Runde je Test, Anhänge an Runde 1) verändert Verifikationen und Lücken nicht und ist wiederholbar prüfbar.
- Alle neuen Texte sind auf Englisch, Deutsch und Niederländisch verfügbar. Die vier Ergebniswerte bleiben englisch (wie in PROJ-3).
- Barrierefreiheit wie im restlichen Produkt (WCAG 2.1 AA als Richtlinie).
- Die Detailansicht mit 20 Runden und 200 Verlaufseinträgen öffnet in unter 2 Sekunden auf der Testumgebung.

## Open Questions

- [ ] Keine offenen Fragen. Entschieden: „Erkannt durch“ kommt aus der Referenzliste „Detection technologies“ und ist verlinkt, die Zeitleiste braucht aktuell keine Filter, und der Wechsel von „Offen“ auf „Verdeckt“ hat einen Bestätigungsdialog.

## Product Decisions

- **Runden statt mehrerer Tests**: Ein Purple-Team-Ablauf ist ein Test mit mehreren Versuchen; so bleibt die Verbesserung der Erkennung an einem Ort nachvollziehbar (2026-11-22).
- **Jüngste abgeschlossene Runde maßgebend**: Das entspricht der Regel „der jüngste Test entscheidet“ aus PROJ-3 und lässt eine Lücke nach einer erfolgreichen Folgerunde schließen (2026-11-22).
- **Zusammenarbeit je Kampagne mit Standard „Verdeckt“**: Beide Arbeitsweisen (blind und Purple Team) sind legitim; der bisherige Schutz aus PROJ-3 bleibt Standard (2026-11-22).
- **Kommentare unveränderlich, nur Admins entfernen**: Der Verlauf dient der Nachvollziehbarkeit; ein Entfernen bleibt als Eintrag sichtbar (2026-11-22).
- **Keine Benachrichtigungen**: Aufwand und Nutzen stehen in keinem Verhältnis zur ersten Fassung; die Seite wird beim Arbeiten ohnehin geöffnet (2026-11-22).
- **Nur eine Runde gleichzeitig offen**: Verhindert Verwirrung darüber, welche Runde gilt, und hält das aktuelle Ergebnis eindeutig (2026-11-22).
- **„Erkannt durch“ aus der Referenzliste „Detection technologies“, verlinkt**: Erkennungen sind einheitlich benannt, filterbar und mit den Use Cases verbunden, statt als Freitext zu verwildern (2026-11-22).
- **Zeitleiste ohne Filter**: Der Verlauf ist kurz genug, Filter sind erst bei Bedarf sinnvoll (2026-11-22).
- **Layout nach VECTR (zwei Spalten, Rundenleiste, Verlauf)**: Vertraute Arbeitsweise für Red- und Blue-Teams; Definition eingeklappt, weil sie sich zwischen Runden nicht ändert (2026-11-22).
- **Startzeit zählt als Ausführungszeit, Endzeit optional**: Verifikation, Time to detect und Reihenfolge der Runden brauchen einen eindeutigen Zeitpunkt (2026-11-22).
