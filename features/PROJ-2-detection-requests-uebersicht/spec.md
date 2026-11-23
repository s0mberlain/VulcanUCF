# PROJ-2: Übersicht aller Detection Requests

**Status:** Planned
**Created:** 2026-11-20

## Requirements
- PROJ-1 (Detection Requests aktionierbar machen): Titel, Beschreibung, Implementierungsstatus und Statusänderung müssen vorhanden sein.

## User Stories
- Als Analyst möchte ich alle Detection Requests über alle Systeme an einer Stelle sehen, damit ich die ausstehende Arbeit überblicke, ohne jedes System einzeln zu öffnen.
- Als Analyst möchte ich die Liste nach Status, System und Titel filtern und nach Risiko sortieren, damit ich das Wichtigste zuerst bearbeite.
- Als Analyst möchte ich den Status eines Requests direkt in der Übersicht ändern, damit ich beim Abarbeiten nicht zwischen Seiten wechseln muss.
- Als Auditor möchte ich die Übersicht lesen können, damit ich den Umsetzungsstand nachvollziehen kann, ohne etwas ändern zu können.
- Als Teammitglied möchte ich eine gefilterte Ansicht als Link weitergeben, damit andere genau dieselbe Liste sehen.

## Out of Scope
- Requests aus Entwürfen und aus älteren, nicht mehr aktuellen Interviews.
- Anlegen, Bearbeiten oder Löschen von Requests (Titel, Beschreibung, Bedrohung). Das bleibt im Interview (PROJ-1).
- Gruppierung nach System (die Liste ist flach).
- Statushistorie, Zuweisung an Personen, Fälligkeitsdaten, Priorität über den Risikowert hinaus.
- Export (CSV, PDF) der Übersicht.
- Benachrichtigungen bei neuen oder geänderten Requests.
- Änderung der Systemseite (sie bleibt wie in PROJ-1, bekommt nur einen Link).

## Acceptance Criteria

### Menü und Zugriff
- [ ] AK-1: Angenommen ein angemeldeter Benutzer mit beliebiger Rolle (Admin, Analyst, Auditor), wenn er das Menü ansieht, dann hat der Eintrag „Use cases“ einen Auf-/Zuklappen-Schalter, und der aufgeklappte Eintrag zeigt eingerückt den Unterpunkt „Detection requests“, der die Übersicht öffnet.
- [ ] AK-2: Angenommen ein Auditor, wenn er die Übersicht öffnet, dann sieht er alle Requests, aber keine Schaltfläche zum Ändern des Status.
- [ ] AK-3: Angenommen die Übersicht ist geöffnet, wenn das Menü betrachtet wird, dann ist „Use cases“ aufgeklappt und der Unterpunkt „Detection requests“ als aktuelle Seite hervorgehoben.
- [ ] AK-3a: Angenommen das Menü, wenn der Benutzer den Schalter bei „Use cases“ bedient (Maus oder Tastatur), dann klappt der Unterpunkt auf oder zu; der Schalter nennt seinen Zustand für Screenreader, und ein Klick auf „Use cases“ selbst öffnet weiter die Use-Case-Seite.

### Inhalt
- [ ] AK-4: Angenommen ein System mit abgeschlossenem Interview, wenn die Übersicht geöffnet wird, dann erscheint jeder Request des zuletzt abgeschlossenen Interviews dieses Systems als eine Zeile mit Titel, System, Bedrohung (Komponente / Kategorie), Risikowert der Bedrohung, Status und „zuletzt geändert“ (Person und Datum).
- [ ] AK-5: Angenommen ein System mit einem Entwurf, der einen noch nicht abgeschlossenen Request enthält, wenn die Übersicht geöffnet wird, dann erscheint dieser Request nicht.
- [ ] AK-6: Angenommen ein System ohne abgeschlossenes Interview, wenn die Übersicht geöffnet wird, dann erscheinen von diesem System keine Requests.
- [ ] AK-7: Angenommen ein Request, der in einem Re-Interview entfernt und abgeschlossen wurde, wenn die Übersicht geöffnet wird, dann erscheint er nicht.
- [ ] AK-8: Angenommen ein Request, der in mehreren Interviews desselben Systems vorkommt, wenn die Übersicht geöffnet wird, dann erscheint er genau einmal und mit seinem aktuellen Status.
- [ ] AK-9: Angenommen ein Request ohne Risikowert (Bedrohung unbewertet), wenn die Übersicht geöffnet wird, dann zeigt die Spalte „–“.
- [ ] AK-10: Angenommen ein Request mit Beschreibung, wenn der Benutzer die Zeile aufklappt, dann sieht er die Beschreibung als reinen Text mit erhaltenen Zeilenumbrüchen, außerdem Statusnotiz und verknüpften Use Case oder Regel, sofern vorhanden.
- [ ] AK-11: Angenommen die Übersicht, wenn der Benutzer auf den Systemnamen einer Zeile klickt, dann öffnet sich die Seite dieses Systems.

### Filter, Zähler, Sortierung
- [ ] AK-12: Angenommen die Übersicht wird ohne Vorgaben geöffnet, wenn sie geladen ist, dann zeigt sie nur Requests mit „Offen“ und „In Bearbeitung“, von allen Systemen, ohne archivierte Systeme.
- [ ] AK-13: Angenommen die Übersicht, wenn sie geladen ist, dann zeigt sie pro Status (Offen, In Bearbeitung, Umgesetzt, Abgelehnt, Nicht umsetzbar) einen Zähler mit der Anzahl der Requests.
- [ ] AK-14: Angenommen ein Statuszähler, wenn der Benutzer darauf klickt, dann wird dieser Status zum Filter hinzugefügt oder daraus entfernt, und die Liste passt sich an.
- [ ] AK-15: Angenommen ein gewähltes System, ein Suchtext oder der Archiv-Schalter, wenn die Zähler berechnet werden, dann zählen sie nur Requests, die zu diesen Filtern passen (unabhängig vom Statusfilter).
- [ ] AK-16: Angenommen die Übersicht, wenn der Benutzer ein System aus der Auswahl wählt, dann zeigt die Liste nur Requests dieses Systems.
- [ ] AK-17: Angenommen die Übersicht, wenn der Benutzer einen Suchtext eingibt, dann zeigt die Liste nur Requests, deren Titel den Text enthält (ohne Beachtung der Groß- und Kleinschreibung).
- [ ] AK-18: Angenommen die Übersicht ohne Archiv-Schalter, wenn archivierte Systeme Requests haben, dann erscheinen diese nicht; mit eingeschaltetem Schalter „Archivierte Systeme einblenden“ erscheinen sie mit der Kennzeichnung „Archiviert“ am Systemnamen.
- [ ] AK-19: Angenommen die Übersicht ohne gewählte Sortierung, wenn die Liste angezeigt wird, dann steht der Request mit dem höchsten Risikowert oben, bei Gleichstand sortiert nach Systemname und dann Titel; Requests ohne Risikowert stehen am Ende.
- [ ] AK-20: Angenommen die Spaltenköpfe Titel, System, Risikowert, Status und zuletzt geändert, wenn der Benutzer auf einen Kopf klickt, dann wird danach aufsteigend sortiert, bei erneutem Klick absteigend.

### Status ändern
- [ ] AK-21: Angenommen ein Admin oder Analyst und ein Request eines nicht archivierten Systems, wenn er den Status ändern will, dann öffnet sich derselbe Dialog wie in PROJ-1 mit Status, Notiz und optionaler Verknüpfung; bei „Abgelehnt“ und „Nicht umsetzbar“ ist eine Begründung Pflicht.
- [ ] AK-22: Angenommen ein gespeicherter Statuswechsel, wenn die neue Liste angezeigt wird, dann bleibt die Zeile sichtbar, auch wenn der neue Status nicht zum Filter passt, und ist als „soeben geändert“ gekennzeichnet; die Zähler zeigen die neuen Werte.
- [ ] AK-23: Angenommen eine als „soeben geändert“ gekennzeichnete Zeile, wenn die Seite neu geladen oder ein Filter geändert wird, dann entspricht die Liste wieder streng den Filtern und die Zeile erscheint nur, wenn sie passt.
- [ ] AK-24: Angenommen ein Request eines archivierten Systems, wenn die Übersicht ihn zeigt, dann gibt es keine Schaltfläche zum Ändern des Status.
- [ ] AK-25: Angenommen ein Statuswechsel schlägt fehl (Netzwerk oder Server), wenn der Benutzer speichert, dann erscheint eine Fehlermeldung, der angezeigte Status bleibt unverändert und die Eingaben im Dialog bleiben erhalten.
- [ ] AK-26: Angenommen ein Request, dessen Status inzwischen von jemand anderem geändert wurde, wenn die Seite neu geladen wird, dann zeigt sie den aktuellen Status samt „zuletzt geändert von X am Y“ (letzte Änderung gewinnt, wie in PROJ-1).

### Link und Adresse
- [ ] AK-27: Angenommen gewählte Filter (Status, System, Suchtext, Sortierung, Archiv-Schalter), wenn die Adresse kopiert und in einem neuen Fenster geöffnet wird, dann zeigt die Übersicht dieselben Filter und Sortierung.
- [ ] AK-28: Angenommen mehrere Filteränderungen nacheinander, wenn der Benutzer den Zurück-Button des Browsers nutzt, dann kehrt die Ansicht zum vorherigen Filterstand zurück.
- [ ] AK-29: Angenommen die Seite eines Systems mit Requests, wenn der Benutzer „Alle Requests anzeigen“ wählt, dann öffnet sich die Übersicht, gefiltert auf dieses System (Statusfilter wie im Standard).

### Leere Zustände und Menge
- [ ] AK-30: Angenommen es gibt noch keinen Request in irgendeinem System, wenn die Übersicht geöffnet wird, dann erscheint ein erklärender Text, dass Requests im Threat-Modelling-Interview angelegt werden, mit einem Verweis zu „Threat modelling“.
- [ ] AK-31: Angenommen es gibt Requests, aber keiner passt zu den Filtern, wenn die Liste angezeigt wird, dann erscheint ein Hinweis „Keine Requests mit diesen Filtern“ mit einer Schaltfläche, die die Filter auf den Standard zurücksetzt.
- [ ] AK-32: Angenommen mehr als 50 passende Requests, wenn die Liste angezeigt wird, dann stehen zunächst 50 Zeilen da, und „Mehr anzeigen“ lädt weitere; die Zähler nennen immer die Gesamtzahl.

## Edge Cases
- EC-1: Ein System wird archiviert, während die Übersicht offen ist: nach dem nächsten Laden ist es ausgeblendet; eine Statusänderung auf dessen Request wird serverseitig weiter akzeptiert (wie in PROJ-1), die Oberfläche bietet sie aber nicht mehr an.
- EC-2: Der Request wird zwischenzeitlich im Interview gelöscht und das Interview neu abgeschlossen, während der Benutzer den Dialog offen hat: das Speichern schlägt mit einer verständlichen Meldung fehl, der Benutzer kann neu laden.
- EC-3: Sehr langer Titel (200 Zeichen) oder sehr lange Beschreibung: die Zeile umbricht, die Tabelle erzeugt keinen waagerechten Scrollbalken der Seite; auf schmalen Bildschirmen (360 px) bleibt jede Zeile lesbar.
- EC-4: Der Link zu einem Systemfilter verweist auf ein gelöschtes oder unbekanntes System: die Übersicht zeigt den Standard und einen Hinweis, dass das System nicht gefunden wurde.
- EC-5: Ungültige Werte in der Adresse (unbekannter Status, unbekannte Sortierung): sie werden ignoriert und durch den Standard ersetzt.
- EC-6: Zwei Systeme mit demselben Namen gibt es nicht (Namen sind eindeutig), die Systemauswahl ist daher eindeutig.
- EC-7: Verknüpfter Use Case oder Regel wurde gelöscht: die Zeile zeigt den Code mit „gelöscht“ wie in PROJ-1.
- EC-8: Ein Request mit Statuswechsel, dessen System im Filter nicht mehr passt, nachdem der Benutzer das System im Filter wechselt: die Markierung „soeben geändert“ entfällt (AK-23).

## Technical Requirements
- Die Übersicht liest dieselben Daten wie die Systemseite (letztes abgeschlossenes Interview, aktueller Status aus PROJ-1), damit Zahlen auf beiden Seiten übereinstimmen.
- Die Übersicht lädt auch bei einigen hundert Requests spürbar schnell (Richtwert: unter 2 Sekunden).
- Alle Texte in den vorhandenen Sprachen (de, nl, en).
- Bedienbar per Tastatur, Statusfarben nicht als einziges Merkmal (der Status steht im Text), wie in PROJ-1.

## Open Questions
- [x] Menü: Der Unterpunkt klappt unter „Use cases“ auf (entschieden 2026-11-20).
- [x] Seitengröße 50 Zeilen (AK-32): bestätigt.
- [x] Anzahl offener Requests außerhalb der Übersicht (Dashboard): nein.

## Product Decisions
- Quelle sind die Requests des zuletzt abgeschlossenen Interviews je System: gleiche Quelle wie die Systemseite, keine abweichenden Zahlen; Entwürfe sind noch nicht verbindlich (2026-11-20).
- Eigene Seite, aufklappbarer Unterpunkt von „Use cases“, für alle Rollen sichtbar: auf Wunsch des Nutzers; Lesezugriff entspricht dem auf Systeme und Interviews, Ändern bleibt Admin und Analyst (2026-11-20).
- Tabelle mit Standardfilter „Offen“ und „In Bearbeitung“, Zähler als Filter, Vorsortierung nach Risikowert: die Seite soll ausstehende Arbeit zeigen und das Wichtigste zuerst (2026-11-20).
- Statusänderung direkt in der Übersicht, geänderte Zeile bleibt bis zum nächsten Laden sichtbar: kein Wegspringen der Liste, Fehlbedienung sofort korrigierbar (2026-11-20).
- Archivierte Systeme standardmäßig ausgeblendet, einblendbar, ohne Änderungsrecht: dort wird nichts mehr umgesetzt (2026-11-20).
- Filter in der Adresse, Link von der Systemseite: gefilterte Ansichten lassen sich teilen und verlinken (2026-11-20).
- Leere Zustände, Fehlerfall, Seitengröße 50 und Randfälle bei ungültigen Adressparametern sind Annahmen des Spec-Autors und im Interview nicht besprochen (2026-11-20).
