# PROJ-5: Aufgaben an Use Cases und Regeln

**Status:** Done
**Created:** 2026-11-24
**Issue:** #74

## Zusammenfassung
Analysten hängen Aufgaben (Review, Tuning, Einstellungen anpassen, Sonstiges) an L2 Use Cases und L3 Regeln. Eine Aufgabe hat einen Titel, einen Markdown-Text, Ersteller und Erstellungsdatum, ein optionales Fälligkeitsdatum und optional eine zuständige Person. Eine zentrale Übersicht zeigt alle offenen Aufgaben.

## User Stories
- Als Analyst möchte ich an einem Use Case oder einer Regel eine Aufgabe anlegen, damit nötige Arbeit (Review, Tuning) nicht vergessen wird.
- Als Analyst möchte ich eine Aufgabe einer Person zuweisen und ein Fälligkeitsdatum setzen, damit klar ist, wer was bis wann erledigt.
- Als Analyst möchte ich alle offenen Aufgaben an einer Stelle sehen und nach Zuständigkeit, Art und Überfälligkeit filtern.
- Als Auditor möchte ich Aufgaben lesen, aber nicht ändern.

## Entscheidungen
- Aufgaben gibt es an L2 Use Cases **und** L3 Regeln (Entscheidung vom 2026-11-24).
- Zuständig sein können aktive Admins und Analysten.
- Löschen dürfen der Ersteller und Admins; erledigen, wieder öffnen und bearbeiten dürfen alle Admins und Analysten.
- Wird ein Use Case oder eine Regel gelöscht, werden seine Aufgaben mit gelöscht.
- Jede Änderung steht im Audit-Log (Entität `task`).

## Acceptance Criteria
- [x] AK-1: Auf der Regelseite und in der L2-Ansicht der Use-Case-Seite gibt es einen Bereich „Tasks“ mit den offenen Aufgaben; erledigte lassen sich einblenden.
- [x] AK-2: Admins und Analysten legen dort Aufgaben an (Art, Titel, Fälligkeit, Zuständig, Markdown-Beschreibung); Auditoren sehen keine Schaltflächen und erhalten 403 von der API.
- [x] AK-3: Eine Aufgabe zeigt Ersteller, Erstellungsdatum, Zuständige, Fälligkeit (überfällig hervorgehoben) und nach Erledigung wer sie wann erledigt hat.
- [x] AK-4: Die Seite „Tasks“ (Menü „Daily work“) listet Aufgaben mit Filtern Status (offen/erledigt/alle), Zuständig (alle, ich, niemand, Person), Art und Suche; Filter stehen in der URL.
- [x] AK-5: Kennzahlen oben: offene Aufgaben, mir zugewiesen, überfällig; ein Klick setzt den Filter.
- [x] AK-6: Der Menüeintrag zeigt die Zahl der offenen Aufgaben, die mir zugewiesen sind; das Dashboard nennt überfällige und mir zugewiesene Aufgaben unter „Needs attention“.
- [x] AK-7: Sortierung: fällige zuerst (älteste Fälligkeit oben), danach die neuesten ohne Fälligkeit.

## API
- `GET /api/tasks?status=open|done|all&assignee=<user>|-&kind=&overdue=true`
- `GET|POST /api/{l2|l3}/{code}/tasks`, `PATCH|DELETE /api/tasks/{id}`, `GET /api/tasks/assignees`
