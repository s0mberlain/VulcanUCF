# PROJ-3: Use-Case-Verifikation durch Tests (Kampagnen, Quick Tests, Testbibliothek)

**Status:** Planned
**Created:** 2026-11-22

## Zusammenfassung

Vulcan UCF bekommt eine Testfunktion nach dem Vorbild von [VECTR](https://github.com/securityriskadvisors/VECTR): Das SOC prüft vorhandene Detection-Regeln mit echten Angriffssimulationen und deckt dabei Erkennungslücken auf. Es gibt zwei Wege:

- **Kampagnen**: größere, geplante Szenarien aus mehreren Testfällen. Externe Red-Teamer führen die Tests aus, das Blue Team (Analysten) trägt die Ergebnisse ein.
- **Quick Tests**: einzelne Tests, die ein Analyst spontan und ohne Kampagne durchführt und sofort einträgt.

Wiederverwendbare Testvorlagen liegen in einer **Testbibliothek**. Jedes Testergebnis wird mit den geprüften L3-Regeln verknüpft, und zwar je Regel mit den **Scopes**, die der Test tatsächlich abdeckt. Erfolgreiche Tests **verifizieren die Regeln automatisch**, aber nur für die abgedeckten Scopes und nur für den Gültigkeitszeitraum der Regel. Nicht erkannte Angriffe erscheinen als **Erkennungslücken**.

Heute gibt es nur die manuelle Verifikation („Verify now“ mit Ergebnis ok oder Probleme). Es gibt keine Möglichkeit, Tests zu planen, auszuführen und festzuhalten.

## Begriffe

| Begriff | Bedeutung |
|---|---|
| Testfall (Test) | Ein einzelner Test mit Titel, **einer** ATT&CK-Technik (Pflicht), Vorgehen, Werkzeugen, verknüpften L3-Regeln (je mit abgedeckten Scopes), Red-Team-Feldern und Blue-Team-Feldern. Gehört entweder zu einer Kampagne oder ist ein Quick Test. |
| Kampagne | Benannte Menge von Testfällen mit Beschreibung, geplantem Start und Ende, Status (Geplant, Läuft, Abgeschlossen) und zugewiesenen Red-Team-Konten. |
| Quick Test | Testfall ohne Kampagne. Ausführung und Ergebnis trägt dieselbe Person in einem Formular ein. |
| Testbibliothek | Wiederverwendbare Vorlagen (Titel, Technik, Vorgehen, Werkzeuge, Voraussetzungen und Aufräumen, erwartete Erkennung). Ein Test aus einer Vorlage ist eine Kopie. |
| Red-Team-Felder | Ausführungsstatus (Nicht ausgeführt, Ausgeführt, Nicht ausführbar), Zeitpunkt der Ausführung (Datum und Uhrzeit), Notizen. |
| Blue-Team-Felder | Ergebnis (Blocked, Alerted, Logged, Not detected), Zeitpunkt der Erkennung (Datum und Uhrzeit), Notizen. |
| Scope | Geltungsbereich einer L3-Regel aus der Referenzliste „Scopes“ (z. B. Windows-Server, Linux, Cloud). Eine Regel hat null oder mehrere Scopes. |
| Abgedeckte Scopes | Die Scopes einer Regel, die ein Test tatsächlich geprüft hat. Sie werden je Verknüpfung Test-Regel gewählt (nur Scopes der Regel). |
| Gültigkeitszeitraum | Das Prüfintervall der Regel (Verifikationsintervall in Tagen, sonst der globale Standard). Eine Verifikation aus einem Test gilt so lange, danach ist die Regel wieder fällig. |
| Verifikationsstand einer Regel | Verifiziert (alle Scopes innerhalb des Zeitraums erfolgreich getestet), Teilweise verifiziert (nur ein Teil der Scopes), Probleme gefunden, Fällig. |
| Time to detect | Erkennungszeit minus Ausführungszeit, nur bei Ergebnis Blocked oder Alerted. |
| Erkennungslücke | Test mit Ergebnis Logged oder Not detected, je Kombination aus Regel und Technik. Ohne verknüpfte Regel: Lücke ohne Regel („Technik T… ist durch keine Regel abgedeckt“). |
| Red-Team-Konto | Neue Rolle „Red team“: lokales Konto mit Ablaufdatum, sieht nur zugewiesene Kampagnen. |

## Requirements

- Die bestehende Verifikation (Verlauf `Verifikation` mit Ergebnis ok oder Probleme, „Verify now“, Seite „Verification“) bleibt unverändert und wird um Einträge aus Tests ergänzt.
- ATT&CK-Techniken, Scopes und das Verifikationsintervall an L3-Regeln (vorhanden) liefern die Vorschläge für Testfälle, die Scope-Abdeckung und die Gültigkeit der Verifikation.
- Rollen und Benutzerverwaltung (Seite „Users“, Account-Seite mit Zwei-Faktor-Anmeldung) und der Audit-Log werden um die Rolle „Red team“ erweitert.
- Die vorhandene Anhangsfunktion (Evidenz bei Interviews) wird für Tests wiederverwendet, einschließlich Dateitypen, Größenbegrenzung und gemeinsamem Speicherkontingent.
- Der Streifen „Needs attention“ des Dashboards und die Menüstruktur (Unterpunkte) werden erweitert.

## Rollen und Rechte

| Rolle | Rechte |
|---|---|
| Admin | alles, was ein Analyst darf; legt Red-Team-Konten an, ändert Ablaufdaten, löscht Kampagnen |
| Analyst (Blue Team) | legt Kampagnen, Testfälle, Quick Tests und Bibliotheksvorlagen an und bearbeitet sie; verknüpft Regeln; trägt Ergebnisse ein; steuert den Kampagnenstatus |
| Auditor | liest alle Kampagnen, Tests, Quick Tests, Bibliothek, Lücken und Verifikationen; ändert nichts |
| Red team | sieht nur zugewiesene Kampagnen; legt Testfälle in diesen Kampagnen an; trägt Red-Team-Felder ein; sieht Blue-Team-Ergebnisse und -Anhänge erst nach Abschluss der Kampagne |

## User Stories

- Als Analyst möchte ich eine Kampagne mit Zeitraum anlegen und Use Cases oder Regeln auswählen, damit Vulcan UCF mir pro ATT&CK-Technik passende Testfälle vorschlägt.
- Als Analyst möchte ich Testfälle aus der Testbibliothek übernehmen und eigene als Vorlage speichern, damit ich Vorgehen wiederverwenden kann.
- Als Admin möchte ich ein Red-Team-Konto anlegen, dessen Ablaufdatum der Kampagne folgt, damit externe Tester nur für die Dauer des Auftrags Zugriff haben.
- Als Red-Teamer möchte ich die Testfälle meiner Kampagne sehen, die Ausführung eintragen und eigene Testfälle ergänzen, damit das Blue Team die Ereignisse findet und ich Angriffsideen einbringen kann.
- Als Analyst möchte ich pro Test das Ergebnis und die Erkennungszeit eintragen, damit die verknüpften Regeln automatisch als verifiziert gelten und die Time to detect sichtbar ist.
- Als Analyst möchte ich auf der Regelseite einen Quick Test mit vorbelegter Regel starten, damit ich eine Regel ohne Kampagne prüfen kann.
- Als Analyst möchte ich offene Erkennungslücken aus Tests sehen und ihre Erledigung nachvollziehen, damit ich weiß, wo die Erkennung fehlt.
- Als Analyst oder Auditor möchte ich auf Regel- und Use-Case-Seiten alle Tests samt Ergebnis sehen, damit ich weiß, wann und mit welchem Ergebnis eine Regel zuletzt angegriffen wurde.
- Als Red-Teamer möchte ich nach Abschluss der Kampagne die Ergebnisse meiner Tests sehen, damit wir ein gemeinsames Debriefing machen können.

## Out of Scope

- **Automatische Ausführung** vordefinierter Testfälle. Das Vorgehen bleibt in dieser Spec reiner Text; ob und wie es später maschinenlesbar wird, regelt eine eigene Spec.
- **Berichte**: ATT&CK-Heatmap aus Testergebnissen, Kampagnen-PDF, Dashboard-Kennzahlen zur Erkennungsrate, Trends der Time to detect über viele Tests. Nur die einzelnen Werte am Test sind enthalten.
- **Detection Requests aus Tests** und Verbindung von Tests zu Systemen (Requests hängen an Interview-Bedrohungen eines Systems). Erkennungslücken aus Tests bleiben getrennt von den Lücken-Zahlen der Systeme.
- **White-Box-Modus** (Red-Teamer sehen vollständige Use-Case-Definitionen): Red-Teamer sehen keine Use Cases, Regeln oder Systeme.
- **SSO** für Red-Team-Konten (nur lokale Anmeldung).
- Red-Teamer haben **keinen Zugriff** auf Quick Tests, Testbibliothek, Use Cases, Dashboard und Verifikationsliste und können **keine Regeln verknüpfen** und nichts in die Bibliothek speichern.
- Versionierung der Bibliotheksvorlagen, Vorlagen-Aktualisierung bestehender Tests.
- Kampagnen kopieren oder als Vorlage speichern, Import aus oder Export nach VECTR.
- Benachrichtigungen (E-Mail) bei Zuweisung, Start oder Abschluss; Erinnerungen an Fristen.
- Mehrere ATT&CK-Techniken pro Testfall; Zuweisung einzelner Testfälle an einzelne Red-Teamer.
- Vorschau für Anhänge über Standardbilder hinaus; Suche in Anhängen.
- **Automatische Verifikation von L2-Use-Cases** aus Testergebnissen. L2 zeigt nur eine Zusammenfassung seiner Regeln.
- Änderung der Berechnung von Scores oder Abdeckung.
- Änderung oder Übernahme der Purple-Team-Umsetzung im Branch `Justinas-MagmaBranch` von CyberBaltic (bleibt ein eigener Branch; ein Vergleich beider Umsetzungen erfolgt später).

## Acceptance Criteria

### Menü und Zugriff
- [ ] AK-1: Angenommen ein Admin, Analyst oder Auditor, wenn er das Menü ansieht, dann hat „Verification“ einen Auf-/Zuklappen-Schalter mit den Unterpunkten „Campaigns“, „Quick tests“ und „Test library“, und „Verification“ selbst öffnet weiter die bestehende Verifikationsliste.
- [ ] AK-2: Angenommen ein angemeldeter Red-Teamer, wenn er das Menü ansieht, dann enthält es nur „Campaigns“ und sein Konto; alle anderen Seiten und Schnittstellen sind für ihn gesperrt (Zugriff darauf wird mit „Zugriff verweigert“ abgelehnt, auch bei direktem Aufruf der Adresse).
- [ ] AK-3: Angenommen ein Auditor, wenn er Kampagnen, Tests, Quick Tests und die Bibliothek öffnet, dann sieht er alles, aber keine Schaltfläche zum Anlegen, Ändern oder Löschen.
- [ ] AK-4: Angenommen die Seite „Campaigns“, „Quick tests“ oder „Test library“ ist geöffnet, wenn das Menü betrachtet wird, dann ist der Unterpunkt als aktuelle Seite hervorgehoben und der Eintrag „Verification“ aufgeklappt.

### Testbibliothek
- [ ] AK-5: Angenommen ein Analyst oder Admin, wenn er eine Vorlage anlegt, dann sind Titel und ATT&CK-Technik Pflicht; Vorgehen, Werkzeuge, Voraussetzungen und Aufräumen sowie erwartete Erkennung sind optional.
- [ ] AK-6: Angenommen die Bibliothek mit mehreren Vorlagen, wenn der Benutzer nach Technik filtert oder nach Text in Titel und Vorgehen sucht, dann zeigt die Liste nur die passenden Vorlagen mit Technik, Ersteller und Zahl der Verwendungen.
- [ ] AK-7: Angenommen ein bestehender Test, wenn der Analyst „In Bibliothek speichern“ wählt, dann entsteht eine Vorlage aus Titel, Technik, Vorgehen und Werkzeugen des Tests.
- [ ] AK-8: Angenommen ein Test, der aus einer Vorlage entstand, wenn die Vorlage geändert oder gelöscht wird, dann bleibt der Test unverändert.
- [ ] AK-9: Angenommen ein Red-Teamer, wenn er die Bibliothek aufruft, dann wird der Zugriff verweigert.

### Kampagnen
- [ ] AK-10: Angenommen ein Analyst oder Admin, wenn er eine Kampagne anlegt, dann sind Name (eindeutig), geplanter Start und geplantes Ende (Ende nicht vor Start) Pflicht; Beschreibung und zugewiesene Red-Team-Konten (null oder mehrere) sind optional; die Kampagne hat den Status „Geplant“.
- [ ] AK-11: Angenommen eine Kampagne im Status „Geplant“, wenn der Analyst „Kampagne starten“ wählt, dann wechselt der Status auf „Läuft“.
- [ ] AK-12: Angenommen eine laufende Kampagne, in der jeder Test einen Ausführungsstatus außer „Nicht ausgeführt“ hat und jeder ausgeführte Test ein Ergebnis, wenn der Analyst „Kampagne abschließen“ wählt, dann wechselt der Status auf „Abgeschlossen“.
- [ ] AK-13: Angenommen eine laufende Kampagne mit unvollständigen Tests, wenn der Analyst „Kampagne abschließen“ wählt, dann bleibt der Status „Läuft“ und der Dialog nennt die unvollständigen Tests.
- [ ] AK-14: Angenommen eine abgeschlossene Kampagne, wenn irgendjemand einen Test, ein Ergebnis oder einen Anhang ändern will, dann ist das gesperrt; ein Analyst kann die Kampagne wieder öffnen (Status „Läuft“).
- [ ] AK-15: Angenommen eine Kampagne im Status „Geplant“ oder „Läuft“, wenn der Analyst Ausführung oder Ergebnisse eintragen will, dann geht das nur im Status „Läuft“; im Status „Geplant“ sind Ergebnisfelder gesperrt.
- [ ] AK-16: Angenommen eine Kampagne im Status „Geplant“ oder ohne Test mit Ergebnis, wenn ein Admin sie löscht, dann verschwindet sie samt ihrer Tests; ein Analyst kann sie nicht löschen.
- [ ] AK-17: Angenommen eine Kampagne mit mindestens einem Ergebnis, wenn ein Admin sie löschen will, dann ist das nicht möglich.
- [ ] AK-18: Angenommen die Liste der Kampagnen, wenn sie geöffnet wird, dann zeigt jede Kampagne Name, Status, geplanten Zeitraum, Zahl der Tests und die Zahl je Ergebnis; für Red-Teamer fehlen die Ergebniszahlen, solange die Kampagne nicht abgeschlossen ist.

### Testfälle vorschlagen und anlegen
- [ ] AK-19: Angenommen eine Kampagne im Status „Geplant“ oder „Läuft“, wenn der Analyst L2-Use-Cases oder einzelne L3-Regeln auswählt, dann schlägt Vulcan UCF **einen Testfall pro ATT&CK-Technik** der gewählten Regeln vor, der alle gewählten Regeln mit dieser Technik verknüpft; bei einem L2 zählen alle seine Regeln außer „Retired“.
- [ ] AK-20: Angenommen eine Regel mit einer ersetzten (revoked) Technik-ID, wenn Vorschläge entstehen, dann wird die ersetzende Technik vorgeschlagen; veraltete oder unbekannte Techniken werden nicht vorgeschlagen und als Hinweis gelistet.
- [ ] AK-21: Angenommen gewählte Regeln ohne ATT&CK-Technik, wenn Vorschläge entstehen, dann stehen sie in einer eigenen Liste „Ohne Technik: Test von Hand anlegen“.
- [ ] AK-22: Angenommen eine Technik, für die die Bibliothek Vorlagen enthält, wenn ein Vorschlag entsteht, dann ist er aus der ersten passenden Vorlage vorausgefüllt und der Analyst kann eine andere wählen; ohne Vorlage ist der Titel der Name der Technik und das Vorgehen leer.
- [ ] AK-23: Angenommen eine Technik, zu der die Kampagne schon Tests enthält, wenn Vorschläge entstehen, dann zeigt der Vorschlag „Hier schon getestet (n Tests)“, ist standardmäßig nicht ausgewählt und bietet an, die Regeln einem vorhandenen Test hinzuzufügen.
- [ ] AK-24: Angenommen der Analyst sieht die Vorschläge, wenn er sie übernimmt, ändert oder verwirft, dann entstehen nur die übernommenen Testfälle.
- [ ] AK-25: Angenommen ein Analyst, wenn er einen Test von Hand oder aus der Bibliothek anlegt, dann kann er Titel, Technik, Vorgehen, Werkzeuge und verknüpfte Regeln (null oder mehrere L3-Regeln) angeben und einen Test ohne Ergebnis löschen.
- [ ] AK-25a: Angenommen ein Test mit einer verknüpften Regel, die Scopes hat, wenn der Analyst die Regel verknüpft, dann wählt er die abgedeckten Scopes aus den Scopes dieser Regel (mindestens einen oder „Alle Scopes der Regel“); ohne Auswahl lässt sich die Verknüpfung nicht speichern. Bei Regeln ohne Scopes gibt es keine Auswahl.
- [ ] AK-25b: Angenommen ein Test mit mehreren verknüpften Regeln, wenn die Scopes gewählt werden, dann gilt die Auswahl je Regel (Test A deckt bei Regel 1 „Windows“, bei Regel 2 „Windows, Linux“ ab).
- [ ] AK-25c: Angenommen die Vorschläge einer Kampagne (AK-19), wenn ein Vorschlag mehrere Regeln verknüpft, dann steht für jede Regel mit Scopes die Scope-Auswahl ohne Vorauswahl bereit und ist vor dem Übernehmen zu treffen.
- [ ] AK-26: Angenommen eine Kampagne desselben Red-Teamers, wenn er einen Testfall anlegt, dann sind Titel und Technik Pflicht, Vorgehen und Werkzeuge optional, und der Test erscheint mit der Markierung „Vom Red Team angelegt“ und ohne verknüpfte Regel.
- [ ] AK-27: Angenommen ein vom Red-Teamer angelegter Test, wenn das Blue Team die Kampagne öffnet, dann steht er als offener Punkt „Regeln zuordnen“ in der Kampagne, bis ein Analyst Regeln verknüpft oder bestätigt, dass keine Regel passt.
- [ ] AK-28: Angenommen ein Red-Teamer, wenn er einen eigenen Test ändern oder löschen will, dann geht das nur, solange das Blue Team kein Ergebnis eingetragen hat; Tests anderer Personen kann er nur im Rahmen der Ausführung (Red-Team-Felder) bearbeiten.
- [ ] AK-29: Angenommen ein Red-Teamer, wenn er Regeln verknüpfen oder einen Test in die Bibliothek speichern will, dann ist das nicht möglich.

### Ausführung und Ergebnisse
- [ ] AK-30: Angenommen ein Test in einer laufenden Kampagne, wenn der zugewiesene Red-Teamer (oder ein Analyst) Status, Ausführungszeit (Datum und Uhrzeit) und Notizen einträgt, dann werden sie am Test mit Name und Zeitpunkt des Eintrags gespeichert.
- [ ] AK-31: Angenommen ein ausgeführter Test, wenn der Analyst das Ergebnis (Blocked, Alerted, Logged, Not detected), die Erkennungszeit und Notizen einträgt, dann werden sie am Test gespeichert.
- [ ] AK-32: Angenommen ein Test, der nicht „Ausgeführt“ ist, wenn der Analyst ein Ergebnis eintragen will, dann ist das nicht möglich.
- [ ] AK-33: Angenommen die Erkennungszeit liegt vor der Ausführungszeit, wenn der Analyst speichert, dann erscheint eine Fehlermeldung an dem Feld und nichts wird gespeichert.
- [ ] AK-34: Angenommen ein Test mit Ergebnis Blocked oder Alerted und beiden Zeiten, wenn der Test angezeigt wird, dann steht die Time to detect am Test; bei Logged oder Not detected steht dort „–“.
- [ ] AK-35: Angenommen eine nicht abgeschlossene Kampagne, wenn ein Red-Teamer einen Test ansieht, dann sieht er weder Ergebnis, Erkennungszeit, Blue-Team-Notizen noch Blue-Team-Anhänge; auch Schnittstellen liefern diese Daten nicht aus.
- [ ] AK-36: Angenommen eine abgeschlossene Kampagne, wenn ein zugewiesener Red-Teamer sie öffnet, dann sieht er Ergebnisse, Erkennungszeiten, Notizen und Anhänge des Blue Teams (nur lesend).
- [ ] AK-37: Angenommen mehrere Red-Teamer in einer Kampagne, wenn sie arbeiten, dann sehen sie gegenseitig ihre Einträge und Testfälle (sie arbeiten als ein Team).

### Automatische Verifikation
- [ ] AK-38: Angenommen ein Test mit Ergebnis Blocked oder Alerted, wenn das Ergebnis gespeichert wird, dann zählen für jede verknüpfte Regel **nur die abgedeckten Scopes** als erfolgreich getestet, und zwar mit dem Datum der Ausführung.
- [ ] AK-39: Angenommen eine Regel mit mehreren Scopes, von denen nur ein Teil durch erfolgreiche Tests abgedeckt ist, wenn der Verifikationsstand berechnet wird, dann lautet er „Teilweise verifiziert (n von m Scopes)“ und nennt die nicht abgedeckten Scopes; „Zuletzt verifiziert“ der Regel wird dadurch **nicht** gesetzt.
- [ ] AK-40: Angenommen eine Regel, deren Scopes alle durch erfolgreiche Tests innerhalb des Gültigkeitszeitraums abgedeckt sind (auch durch verschiedene Tests), wenn der Verifikationsstand berechnet wird, dann lautet er „Verifiziert“; das Datum „Zuletzt verifiziert“ ist das Ausführungsdatum des **ältesten** der jeweils neuesten erfolgreichen Tests der Scopes (die Regel ist so aktuell wie ihr ältester Scope), und ein Verifikationseintrag „ok“ mit Hinweis „aus Test: Titel“ entsteht.
- [ ] AK-41: Angenommen eine Regel ohne Scopes, wenn ein verknüpfter Test Blocked oder Alerted ergibt, dann ist sie verifiziert (Eintrag „ok“, Datum der Ausführung).
- [ ] AK-42: Angenommen ein Test mit Ergebnis Logged oder Not detected, wenn das Ergebnis gespeichert wird, dann erhält jede verknüpfte Regel einen Verifikationseintrag „Probleme gefunden“ mit Hinweis auf den Test und die betroffenen Scopes; die Regel gilt dann nicht als verifiziert, bis ein späterer erfolgreicher Test die betroffenen Scopes abdeckt.
- [ ] AK-43: Angenommen ein Test mit Status „Nicht ausgeführt“ oder „Nicht ausführbar“, wenn er gespeichert wird, dann entsteht keine Verifikation und keine Scope-Abdeckung.
- [ ] AK-44: Angenommen eine Regel mit Verifikationsstand „Verifiziert“ oder „Teilweise verifiziert“, wenn ihr Gültigkeitszeitraum (Verifikationsintervall der Regel, sonst der globale Standard) seit der Ausführung eines abdeckenden Tests verstrichen ist, dann gilt dieser Scope nicht mehr als abgedeckt, der Stand fällt entsprechend (bis hin zu „Fällig“), und die Regel erscheint wie bisher in der Liste der fälligen Verifikationen.
- [ ] AK-45: Angenommen ein Test mit Ergebnis, dessen Ergebnis oder abgedeckte Scopes später geändert werden oder aus dem eine Regel entfernt wird, wenn der Analyst speichert, dann werden Scope-Abdeckung, Verifikationsstand und Verifikationseintrag der betroffenen Regeln neu berechnet, ohne doppelte Einträge anzulegen; wird eine Regel hinzugefügt, entsteht ihr Eintrag.
- [ ] AK-45a: Angenommen eine Regel im Status „Retired“, wenn sie von Hand mit einem Test verknüpft wird und ein Ergebnis vorliegt, dann gelten dieselben Regeln.
- [ ] AK-45b: Angenommen ein L2-Use-Case, wenn Tests seiner Regeln Ergebnisse haben, dann ändert sich sein Datum „Zuletzt verifiziert“ **nicht** automatisch; er zeigt nur die Zusammenfassung (AK-71). Die manuelle Verifikation des L2 („Verify now“) funktioniert weiter wie bisher.
- [ ] AK-45c: Angenommen die Regelseite, wenn sie geöffnet wird, dann zeigt sie je Scope den Stand (abgedeckt bis Datum / nicht abgedeckt / abgelaufen / Problem) mit Verweis auf den abdeckenden Test.
- [ ] AK-45d: Angenommen die manuelle Verifikation („Verify now“), wenn ein Analyst sie für eine Regel einträgt, dann gilt sie wie bisher für die ganze Regel und ersetzt keine Scope-Abdeckung aus Tests; beide Quellen stehen im Verlauf.

### Erkennungslücken
- [ ] AK-46: Angenommen ein Test mit Ergebnis Logged oder Not detected und verknüpfter Regel, wenn er gespeichert wird, dann gilt für jede verknüpfte Regel und jeden abgedeckten Scope eine offene Lücke für die Kombination aus Regel, Scope und Technik (bei Regeln ohne Scopes aus Regel und Technik).
- [ ] AK-47: Angenommen ein Test mit Ergebnis Not detected ohne verknüpfte Regel, wenn er gespeichert wird, dann entsteht eine offene Lücke ohne Regel für die Technik.
- [ ] AK-48: Angenommen eine offene Lücke, wenn ein späterer Test derselben Technik auf derselben Regel **und demselben Scope** (oder bei Lücke ohne Regel mit derselben Technik) das Ergebnis Blocked oder Alerted hat, dann ist die Lücke erledigt und verweist auf den erledigenden Test; ein erfolgreicher Test auf einem anderen Scope erledigt sie nicht.
- [ ] AK-49: Angenommen eine offene Lücke, wenn ein Analyst sie mit Begründung als „akzeptiert“ markiert, dann zählt sie nicht mehr als offen und bleibt mit Begründung, Person und Datum in der Historie.
- [ ] AK-50: Angenommen die Seite „Quick tests“ und die Kampagnenansicht, wenn der Benutzer nach „offene Lücken“ filtert, dann sieht er nur Tests mit offenen Lücken.
- [ ] AK-51: Angenommen offene Lücken aus Tests, wenn das Dashboard geöffnet wird, dann zeigt der Streifen „Needs attention“ die Zeile „n Erkennungslücken aus Tests“ mit Link auf die gefilterte Übersicht; die Lücken-Zahlen der Systeme ändern sich dadurch nicht.

### Quick Tests
- [ ] AK-52: Angenommen ein Analyst oder Admin, wenn er auf der Regelseite „Quick test“ wählt, dann öffnet sich das Formular mit der Regel verknüpft und, falls vorhanden, ihrer ATT&CK-Technik vorbelegt.
- [ ] AK-53: Angenommen die Seite „Quick tests“, wenn der Analyst „Neuer Quick test“ wählt, dann kann er Titel, Technik, Vorgehen und Werkzeuge von Hand eintragen oder eine Bibliotheksvorlage übernehmen und Regeln verknüpfen.
- [ ] AK-54: Angenommen das Quick-Test-Formular, wenn der Analyst Ausführungszeit, Ergebnis, Erkennungszeit und Notizen einträgt und speichert, dann wirken Verifikation und Scope-Abdeckung (AK-38 bis AK-45d) und Lücken (AK-46 bis AK-51) genau wie bei Kampagnentests.
- [ ] AK-55: Angenommen die Seite „Quick tests“, wenn sie geöffnet wird, dann listet sie alle Quick Tests mit Datum, Titel, Technik, verknüpften Regeln, Ergebnis und Person, filterbar nach Ergebnis, Technik und offenen Lücken.
- [ ] AK-56: Angenommen ein Quick Test, wenn er gespeichert ist, dann kann der Analyst ihn über „In Bibliothek speichern“ als Vorlage sichern.

### Red-Team-Konten
- [ ] AK-57: Angenommen ein Admin, wenn er auf der Seite „Users“ ein Konto mit der Rolle „Red team“ anlegt, dann ist ein Ablaufdatum Pflicht; nach der Zuweisung zu einer Kampagne schlägt Vulcan UCF das geplante Ende der spätestens endenden zugewiesenen Kampagne als Ablaufdatum vor (Ende dieses Tages).
- [ ] AK-58: Angenommen ein Red-Team-Konto mit der Einstellung „folgt der Kampagne“, wenn sich das geplante Ende einer zugewiesenen Kampagne ändert oder eine weitere Kampagne zugewiesen wird, dann passt sich das Ablaufdatum automatisch an.
- [ ] AK-59: Angenommen ein Admin setzt das Ablaufdatum von Hand, wenn sich Kampagnen ändern, dann bleibt das Datum fest; die Oberfläche zeigt „fest“ oder „folgt der Kampagne“ an, und „Wieder der Kampagne folgen“ stellt den Standard zurück.
- [ ] AK-60: Angenommen ein Red-Team-Konto ohne zugewiesene Kampagne, wenn es angelegt wird, dann ist das Ablaufdatum ein von Hand eingegebenes Pflichtfeld; ab der ersten Zuweisung bietet Vulcan UCF „folgt der Kampagne“ an.
- [ ] AK-61: Angenommen ein Red-Team-Konto nach seinem Ablaufdatum, wenn jemand sich anmeldet oder eine laufende Sitzung weiterverwendet, dann wird der Zugriff verweigert; das Konto und seine Daten bleiben erhalten, ein Admin kann das Datum verlängern.
- [ ] AK-62: Angenommen eine vor ihrem geplanten Ende abgeschlossene Kampagne, wenn der Zeitpunkt des Abschlusses erreicht ist, dann läuft das Konto trotzdem erst zum geplanten Ende ab.
- [ ] AK-63: Angenommen ein Red-Team-Konto, wenn die Anmeldung per SSO versucht wird, dann ist sie nicht möglich; Anmeldung ist nur lokal, optional mit Zwei-Faktor-Anmeldung.
- [ ] AK-64: Angenommen ein Red-Teamer, der nach Beginn von einer Kampagne entfernt wird, wenn er sich anmeldet, dann sieht er sie nicht mehr; seine bisherigen Einträge bleiben mit seinem Namen erhalten.
- [ ] AK-65: Angenommen ein Red-Team-Konto mit Einträgen, wenn ein Admin es löschen will, dann ist das nicht möglich; er kann es nur sperren.

### Anhänge
- [ ] AK-66: Angenommen ein Test in einer laufenden Kampagne, wenn ein zugewiesener Red-Teamer eine Datei anhängt, dann wird sie als Red-Team-Anhang gespeichert; Analysten hängen Dateien als Blue-Team-Anhänge an (auch bei Quick Tests).
- [ ] AK-67: Angenommen eine Datei, die gegen die Grenzen verstößt (erlaubte Dateitypen wie bei Interview-Anhängen, höchstens 20 MB je Datei, höchstens 50 Dateien je Test, gemeinsames Speicherkontingent), wenn sie angehängt wird, dann erscheint eine Fehlermeldung, die die verletzte Grenze nennt, und nichts wird gespeichert.
- [ ] AK-68: Angenommen ein eigener Anhang in einer laufenden Kampagne, wenn die Person ihn löscht, dann verschwindet er; fremde Anhänge kann sie nicht löschen; in einer abgeschlossenen Kampagne ist das Löschen gesperrt.
- [ ] AK-69: Angenommen ein Blue-Team-Anhang in einer nicht abgeschlossenen Kampagne, wenn ein Red-Teamer den Test ansieht, dann ist der Anhang für ihn weder sichtbar noch herunterladbar.

### Anzeige an Regeln und Use Cases
- [ ] AK-70: Angenommen eine L3-Regel mit Tests, wenn die Regelseite geöffnet wird, dann zeigt ein Abschnitt „Tests“ alle Tests (Datum, Technik, Ergebnis, Kampagne oder „Quick test“, Person) mit offenen Lücken oben und einem Knopf „Quick test starten“.
- [ ] AK-71: Angenommen ein L2-Use-Case, wenn seine Seite geöffnet wird, dann zeigt sie eine Zusammenfassung über seine Regeln: Datum des letzten Tests, Zahl der Tests, Zahl der Regeln je Verifikationsstand (Verifiziert, Teilweise verifiziert, Probleme gefunden, Fällig) und Zahl der offenen Lücken.
- [ ] AK-72: Angenommen der Verifikationsverlauf einer Regel, wenn ein Eintrag aus einem Test stammt, dann trägt er den Hinweis „aus Test: Titel“ mit Link auf den Test und nennt die abgedeckten Scopes.
- [ ] AK-73: Angenommen ein Benutzer ohne Leserecht auf Tests (Red-Teamer), wenn er die Regelseite aufruft, dann wird der Zugriff verweigert (siehe AK-2).

### Nachvollziehbarkeit und gleichzeitige Bearbeitung
- [ ] AK-74: Angenommen Anlegen, Ändern oder Löschen von Kampagnen, Tests, Quick Tests, Vorlagen, Konten, Zuweisungen und Ergebnissen, wenn die Aktion ausgeführt wird, dann steht sie mit Person und Zeitpunkt im Audit-Log; Aktionen von Red-Teamern tragen den Namen des Kontos.
- [ ] AK-75: Angenommen zwei Personen bearbeiten denselben Teil eines Tests (Red-Team-Felder oder Blue-Team-Felder), wenn die zweite speichert, dann erscheint „Dieser Test wurde von X geändert, bitte neu laden“, nichts wird überschrieben, und ihre Eingaben werden zur Wiederherstellung angeboten.
- [ ] AK-76: Angenommen ein Red-Teamer trägt die Red-Team-Felder ein, während ein Analyst die Blue-Team-Felder desselben Tests bearbeitet, wenn beide speichern, dann überschreiben sie sich nicht gegenseitig.

## Edge Cases

- EC-1: Was passiert, wenn eine verknüpfte Regel oder ein Use Case gelöscht wird? Der Test bleibt erhalten und zeigt „Regel gelöscht: CODE“ mit Code und Name zum Zeitpunkt des Löschens; die Verifikationen verschwinden wie bisher mit der Regel, offene Lücken dieser Regel entfallen, eine Lücke ohne Regel bleibt.
- EC-2: Was passiert, wenn ein Test mehrere Regeln verknüpft und das Ergebnis Logged ist? Jede Regel bekommt die Verifikation „Probleme gefunden“ und eine Lücke.
- EC-3: Was passiert, wenn für dieselbe Regel, Technik und denselben Scope mehrere Tests mit gemischten Ergebnissen existieren? Maßgeblich ist der zeitlich letzte Test (nach Ausführungszeit); ein älteres „Not detected“ nach einem neueren „Alerted“ öffnet keine Lücke.
- EC-3a: Was passiert, wenn einer Regel nach erfolgreichen Tests ein neuer Scope hinzugefügt oder einer entfernt wird? Der Stand wird neu berechnet: Ein neuer Scope ist nicht abgedeckt (Stand „Teilweise verifiziert“), ein entfernter Scope zählt nicht mehr; frühere Tests behalten ihre gespeicherte Scope-Auswahl.
- EC-3b: Was passiert, wenn die Referenzliste einen Scope umbenennt oder löscht? Bestehende Tests behalten den gespeicherten Namen; für die Abdeckung zählt der aktuelle Scope-Name der Regel, nicht mehr vorhandene Scopes werden als „nicht mehr an der Regel“ angezeigt.
- EC-3c: Was passiert, wenn ein Test alle Scopes einer Regel wählt, aber nur auf einem System lief? Das liegt in der Verantwortung des Analysten; die Scope-Auswahl ist eine bewusste Aussage („Alle Scopes der Regel“ ist eine eigene Schaltfläche).
- EC-3d: Was passiert, wenn das Prüfintervall der Regel geändert wird? Der Gültigkeitszeitraum verwendet immer das aktuelle Intervall, Verifikationsstand und Fälligkeit werden entsprechend neu berechnet.
- EC-4: Was passiert, wenn ein Test ohne Technik angelegt werden soll? Das ist nicht möglich (Pflichtfeld).
- EC-5: Was passiert, wenn eine Technik später aus ATT&CK entfernt oder ersetzt wird? Bestehende Tests behalten ihre gespeicherte Technik; Vorschläge verwenden die ersetzende Technik (AK-20).
- EC-6: Was passiert, wenn die Kampagne ohne einen einzigen Test abgeschlossen wird? Das ist möglich (AK-12 verlangt nur, dass vorhandene Tests vollständig sind); die Liste zeigt „0 Tests“.
- EC-7: Was passiert bei leeren Zuständen? Ohne Kampagnen erscheint ein Hinweis mit „Kampagne anlegen“, ohne Quick Tests und ohne Vorlagen je ein Hinweis mit der nächsten Handlung; ein Red-Teamer ohne zugewiesene Kampagne sieht „Dir ist noch keine Kampagne zugewiesen“.
- EC-8: Was passiert, wenn der Admin ein Ablaufdatum in der Vergangenheit setzt? Das Konto ist sofort gesperrt; die Oberfläche warnt vor dem Speichern.
- EC-9: Was passiert, wenn eine Red-Team-Sitzung während der Bearbeitung abläuft? Die nächste Speicherung wird abgelehnt, die Eingaben bleiben im Formular erhalten und werden nach neuer Anmeldung zur Wiederherstellung angeboten, soweit das Konto noch gültig ist.
- EC-10: Was passiert, wenn eine Kampagne wieder geöffnet wird? Der Status ist „Läuft“, Ergebnisse und Verifikationen bleiben bestehen, Änderungen passen Scope-Abdeckung und Verifikationen an (AK-45), und Red-Teamer sehen die Ergebnisse wieder nicht.
- EC-11: Was passiert, wenn ein Analyst Ergebnisse einträgt, während die Kampagne „Geplant“ ist? Nicht möglich (AK-15).
- EC-12: Was passiert bei Zeitzonen? Ausführung und Erkennung speichern Datum und Uhrzeit und werden in der Zeitzone des Anzeigenden dargestellt; das Verifikationsdatum ist das Datum der Ausführung in der Zeitzone der Anlage des Tests.
- EC-13: Was passiert, wenn ein Anhang beim Hochladen scheitert (Netzwerk)? Der Test bleibt unverändert, die Fehlermeldung nennt den Grund, die Datei kann erneut gewählt werden.
- EC-14: Was passiert bei sehr vielen Tests? Listen sind seitenweise oder mit „Mehr anzeigen“ und bleiben filterbar; eine Kampagne mit 200 Tests ist bedienbar.

## Technical Requirements

- Alle Rechte (insbesondere die Sichtbarkeit der Blue-Team-Daten für Red-Teamer) werden serverseitig durchgesetzt; die Oberfläche blendet nur aus. Eine direkte Schnittstellenabfrage eines Red-Teamers liefert keine Blue-Team-Daten und keine fremden Kampagnen.
- Die Ablaufprüfung eines Red-Team-Kontos gilt bei jeder Anfrage, nicht nur bei der Anmeldung.
- Dateien und Kontingent nutzen die vorhandene Anhangslogik; es entsteht keine zweite Speicherart.
- Vorgehen und Notizen werden als reiner Text mit erhaltenen Zeilenumbrüchen dargestellt; Inhalte aus Red-Team-Eingaben werden nie als Markup ausgeführt.
- Alle neuen Texte sind auf Englisch, Deutsch und Niederländisch verfügbar.
- Barrierefreiheit wie im restlichen Produkt (WCAG 2.1 AA als Richtlinie): Tastaturbedienung der Listen und Formulare, Fehlermeldungen als Text am Feld.
- Listen laden bei 500 Tests in einer Kampagne ohne spürbare Verzögerung (unter 2 Sekunden auf der Testumgebung).

## Open Questions

- [ ] Wie heißen die vier Ergebnisse (Blocked, Alerted, Logged, Not detected) auf Deutsch? Entschieden ist nur: Das Feld heißt auf Deutsch „Ergebnis“ beziehungsweise „Ergebnisse“. Empfehlung: die vier Werte bleiben in allen Sprachen englisch, mit kurzer deutscher Erklärung als Hilfetext.
- [ ] Vergleich der Umsetzung im Branch `Justinas-MagmaBranch` (CyberBaltic) mit der Umsetzung dieser Spec. Der Branch bleibt unverändert bestehen; die Entscheidung, welche Umsetzung besser ist, wird später getroffen und ist nicht Teil dieser Spec. Der alte Spec-Entwurf auf `claude/project-thread-lnlh81` trägt ebenfalls die Nummer PROJ-3 und bleibt unberührt.
- [ ] Soll die Scope-Abdeckung später auch in die Berechnung der Abdeckung oder Scores eingehen? Aktuell nicht (siehe Out of Scope).

## Product Decisions

- **Neue Spec statt Erweiterung des alten Entwurfs**: Der geschlossene Entwurf „Purple team campaigns“ enthält weder Quick Tests noch die Auto-Verifikation in dieser Form und einen White-Box-Modus, der nicht gewünscht ist; er dient nur als Ideenquelle (2026-11-22).
- **Red-Teamer von Anfang an mit eigener Rolle**: Externe Tester sollen ohne Zugriff auf Use Cases, Dashboard oder andere Systeme arbeiten und nur für die Dauer des Auftrags Zugang haben (2026-11-22).
- **Red-Teamer dürfen Testfälle anlegen, aber keine Regeln verknüpfen**: Sie sehen die Use Cases nicht; die Zuordnung bleibt beim Blue Team und taucht dort als offener Punkt auf (2026-11-22).
- **Blue-Team-Ergebnisse erst nach Abschluss für das Red Team**: Das Debriefing soll gemeinsam stattfinden, und die Ausführung soll nicht auf das Erkennungsergebnis abgestimmt werden (2026-11-22).
- **Quick Tests zählen wie Kampagnentests**: Eine spontane Prüfung ist genauso ein Nachweis (gleiche Verifikation, gleiche Lücken), nur ohne Planungsrahmen und ohne Red-Team-Phase (2026-11-22).
- **Vier Ergebnisse nach VECTR**: Blocked und Alerted gelten als Erfolg und verifizieren, Logged und Not detected als Verifikation „Probleme gefunden“ und Erkennungslücke; „Logged“ ist keine erfolgreiche Erkennung, weil kein Alarm entsteht (2026-11-22).
- **Verifikationsdatum ist das Datum der Ausführung**: So spiegelt „zuletzt verifiziert“ den Zeitpunkt des Angriffs und nicht der Dateneingabe (2026-11-22).
- **Vorlagen sind Kopien**: Ein durchgeführter Test muss nachvollziehbar so bleiben, wie er ausgeführt wurde; deshalb ändern Änderungen an der Vorlage ihn nicht (2026-11-22).
- **Lücken getrennt von den Lücken der Systeme**: Tests gehören zu Regeln, Detection Requests zu Systemen und Interviews; die Verbindung wäre eine eigene Spec (2026-11-22).
- **Ablaufdatum folgt standardmäßig der Kampagne, ein manuelles Datum ist fest**: Spart dem Admin die Pflege und verhindert verwaiste Konten, ohne dass eine bewusste Entscheidung überschrieben wird (2026-11-22).
- **Anhänge in einfacher Form**: Ein Nachweis besteht oft aus Screenshot oder Logauszug; die vorhandene Anhangslogik wird wiederverwendet (2026-11-22).
- **Berichte, automatische Ausführung und Benachrichtigungen ausgeklammert**: Der Nutzen der Erfassung ist unabhängig davon, und jede dieser Funktionen ist eine eigene, später testbare Einheit (2026-11-22).
- **Keine automatische Verifikation für L2-Use-Cases**: Ein L2 bündelt mehrere Regeln; ein Test prüft immer einzelne Regeln und Scopes. L2 zeigt nur die Zusammenfassung seiner Regeln (2026-11-22).
- **Verifikation gilt für den Zeitraum des Use Cases**: Eine Verifikation aus einem Test läuft nach dem Verifikationsintervall der Regel (sonst globaler Standard) ab, genau wie die manuelle; die Regel wird dann wieder fällig (2026-11-22).
- **Verifikation berücksichtigt die Scopes der Regel**: Deckt ein Test nur einen Teil der Scopes ab, gilt die Regel nur teilweise als verifiziert („Teilweise verifiziert (n von m Scopes)“); „Zuletzt verifiziert“ bleibt so alt wie der älteste Scope. Die Scope-Auswahl je Test und Regel ist eine bewusste Entscheidung ohne Vorauswahl, damit nie versehentlich alles als geprüft gilt (2026-11-22).
- **Lücken je Regel, Scope und Technik**: Ein Fehlschlag auf einem Scope soll nicht durch einen Erfolg auf einem anderen Scope verschwinden (2026-11-22).
- **Anhänge mit den üblichen Grenzen**: 20 MB je Datei, 50 Dateien je Test und das gemeinsame Speicherkontingent, wie bei Interview-Anhängen (2026-11-22).
- **Der Branch von CyberBaltic bleibt unverändert bestehen**: Beide Umsetzungen werden später verglichen; diese Spec ist unabhängig davon geschrieben (2026-11-22).
- **Bezeichnung „Ergebnis/Ergebnisse“ auf Deutsch**: Einheitlicher Begriff für das Blue-Team-Feld und die Auswertung in der deutschen Oberfläche (2026-11-22).
