# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Public demo extracted from a production SOC L1 panel. FastAPI + asyncpg + Postgres 15,
vanilla JS frontend, no build step. All data is synthetic except a few genuinely public
CVEs (Log4Shell, PrintNightmare, Citrix Bleed, Zerologon) used as KEV examples — never
describe the data as real, and never add anything resembling real client infrastructure.

## Running it

Docker is the only supported path:

```bash
cp .env.example .env
docker compose up --build      # http://localhost:8000
```

The API auto-seeds on startup when `vuln_state_cache` is empty (`seed_if_empty`), so
there is no manual seed step. Reseed explicitly with:

```bash
docker compose exec -T api python -m seed.generate_seed --reset --yes   # destructive
```

`--reset` requires `--yes`. The seed is deterministic (`SEED = 20260822`).

**Gotcha:** `postgres_host` defaults to `postgres`, which only resolves inside the compose
network. Running uvicorn or the seed script on the host needs `POSTGRES_HOST=localhost`
plus a published Postgres port (compose deliberately does not publish one), or
`POSTGRES_DSN_OVERRIDE`.

## Tests, lint, format

```bash
pip install -r requirements-dev.txt   # pytest + ruff
pytest              # tests/ — currently covers app/scoring.py only
ruff format .
ruff check .
```

ruff is configured in `pyproject.toml`: line-length 100, target py311, rules `E,F,I,B`.
The `UP` (pyupgrade) rules are deliberately off — this codebase uses `Optional[X]` and
`typing.Dict` style, and modernizing it is not in scope. Keep matching that style.
A PostToolUse hook runs `ruff format` on each Python file you edit.

## Deliberate design constraints

Do not "fix" these — they were removed on purpose when extracting the demo:

- **No authentication anywhere.** CORS is `allow_origins=["*"]` and `updated_by` is
  hardcoded to `"visitante-demo"`. Any visitor can create or delete assignments. Do not
  restore auth, audit trail, live Wazuh/EPSS/CISA polling, or email without being asked.
- `/vulnerabilities/summary` and `/vulnerabilities/cves` must keep sharing the
  `_vuln_rows` / `_apply_vuln_filters` helpers in `app/main.py` so KPIs and the table
  never desync. New filtering logic goes in those helpers, not in one route.
- Filtering and aggregation happen in Python over the cached JSONB state in
  `vuln_state_cache` (a single row, `CHECK (id = 1)`) — not in SQL. Only the
  lifecycle/SLA metrics (`patching_metrics`) are real queries.
- Schema lives in `app/vuln_store.py:TABLES_SQL` as `CREATE TABLE IF NOT EXISTS`; there
  are no migrations. `connect()` swallows table-creation failures with a
  `vuln_tables_init_failed` warning, so schema errors surface as empty data, not crashes.
- The scoring formula is `app/scoring.py:priority_score` — `CVSS*5 + EPSS*30 + 20 if KEV`,
  capped at 100, degrading to CVSS-only without EPSS. All weights and thresholds are
  `Settings` fields; change those, not the literals.

## Frontend

- `static/tailwind.css` is a frozen prebuilt artifact — there is no Tailwind source or
  config in this repo and it cannot be regenerated here. **Never edit it, and never use a
  utility class that isn't already in it.** New styling goes in `index.html`'s inline
  `<style>` or `sidebar.css`.
- ApexCharts and the Outfit fonts are vendored on purpose. No CDN references, ever.
- Theme is applied pre-paint by an inline `<head>` script in `index.html` *and* re-applied
  in `theme.js` — both must stay in sync. localStorage keys: `soc.theme` (`light`|`soc`),
  `soc.navCollapsed`.

## Conventions

- Existing code, comments and docstrings are Spanish; **write new comments, docstrings,
  docs and commit messages in English.** Do not mass-translate existing Spanish.
- Spanish stays in API field names, DB status values (`pendiente`, `en_curso`, `parcial`,
  `resuelto`, `aceptado_riesgo`) and UI strings — these are data contracts, not prose.
- Every module starts with `from __future__ import annotations`. Type hints throughout.
- Never commit to `master`. Branch, then open a PR with `gh`.
