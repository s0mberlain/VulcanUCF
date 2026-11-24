# PROJ-6: Verifikation von Log Sources

**Status:** Done
**Created:** 2026-11-24
**Issue:** #75

## Zusammenfassung
Analysten verifizieren Log Sources in festen Abständen. Eine Prüfung umfasst vier Punkte (Log-Eingang, Konfiguration, Filterung, Zuständigkeiten), jeweils OK, Probleme oder nicht anwendbar mit Notiz, dazu eine Gesamtnotiz (Markdown). Eine Übersicht zeigt, welche Log Sources fällig, überfällig oder mit Problemen geprüft sind. Der Status erscheint auch an den Regeln, die eine Log Source nutzen.

## User Stories
- Als Analyst möchte ich eine Log Source mit den vier Prüfpunkten verifizieren und das Ergebnis dokumentieren.
- Als Analyst möchte ich sehen, welche Log Sources überfällig sind oder bei der letzten Prüfung Probleme hatten.
- Als Analyst möchte ich je Log Source eine verantwortliche Stelle und ein eigenes Prüfintervall festlegen.
- Als Admin möchte ich das Standardintervall für alle Log Sources festlegen.
- Als Analyst möchte ich an einer Regel sehen, ob eine ihrer Log Sources überfällig ist oder Probleme hat (Entscheidung vom 2026-11-24).

## Entscheidungen
- Die vier Prüfpunkte sind fest vorgegeben (eine von Admins pflegbare Liste kann später folgen).
- Nur eine Prüfung ohne Probleme zählt als Verifikation und verschiebt die Fälligkeit (wie bei Regeln).
- Status: nie verifiziert, verifiziert, bald fällig (im gewählten Zeitfenster), überfällig, Probleme gefunden (letzte Prüfung).
- An Regeln werden nur „überfällig“ und „Probleme gefunden“ markiert; „nie verifiziert“ nicht, damit vor der ersten Prüfrunde nicht jede Regel eine Warnung trägt. Die Bewertung (Scores) der Regeln ändert sich nicht.
- Standardintervall: App-Einstellung `log_sources.verification` (Admin, Seite Settings), sonst DEFAULT_VERIFICATION_DAYS.

## Acceptance Criteria
- [x] AK-1: Menü Verification → „Log sources“ öffnet die Übersicht mit Kennzahlen (Anteil rechtzeitig verifiziert, überfällig, Probleme, fällig im Fenster), Fenster 30/90 Tage und Suche.
- [x] AK-2: Die Tabelle zeigt je Log Source Verantwortliche, Nutzung (Regeln, Systeme), letzte Verifikation, Fälligkeit, eigenes Intervall und Status.
- [x] AK-3: „Verify now“ öffnet den Dialog mit den vier Prüfpunkten; ein Punkt mit „Issues“ macht die ganze Prüfung zu „Issues found“.
- [x] AK-4: Ein Klick auf den Namen zeigt Verantwortliche und Intervall (änderbar für Admins/Analysten) und den Prüfverlauf.
- [x] AK-5: Auf der Regelseite erscheint ein Hinweis, wenn eine Log Source der Regel überfällig ist oder Probleme hat; die Chips der Log Sources sind markiert, ebenso in der Regeltabelle der Use-Case-Seite.
- [x] AK-6: Das Dashboard nennt unter „Needs attention“ die Zahl der überfälligen Log Sources und der mit Problemen.
- [x] AK-7: Auditoren sehen alles, ändern nichts (403); jede Änderung steht im Audit-Log (Entität `log_source`).

## API
- `GET /api/log-sources/verification?within_days=30`
- `POST /api/log-sources/{id}/verify`, `GET /api/log-sources/{id}/verifications`, `PUT /api/log-sources/{id}/profile`
- `GET|PUT /api/log-sources/settings`
