# Learning Journal

One folder per week: `journal/week-NN/`.

Each week folder holds:
- `README.md` — the weekly log (copied from `00-program/weekly-study-log.md`)
- any notes, diagrams, lab code, test output (sanitized — no real secrets or personal data)

Start a new week:

```powershell
$n = "02"; New-Item -ItemType Directory "journal/week-$n"; Copy-Item 00-program/weekly-study-log.md "journal/week-$n/README.md"
```

Then tick the week in [`PROGRESS.md`](../PROGRESS.md) when its build/prove item is done.

| Week | Topic | Status |
|---|---|---|
| [01](week-01/) | AI/ML/GenAI landscape, lifecycle, actors and assets | In progress |
