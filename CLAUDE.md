# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**Patch Genius** — vulnerability and patch tracking over a Wazuh deployment the operator
configures at runtime. FastAPI + asyncpg + Postgres 15, vanilla JS frontend, no build step.

There is no demo or sample data: the dashboard shows what the configured Wazuh reports, or
nothing. Never reintroduce a synthetic seed, and never write a real host, IP or credential
into the repository — it is public and every deployment points at a different Wazuh.

## Running it

Docker is the only supported path:

```bash
cp .env.example .env
./scripts/setup-env.sh
docker compose up --build      # http://localhost:8000
```

`./scripts/setup-env.sh` generates `.env` with a Fernet `APP_SECRET_KEY` and a bootstrap
admin password. Every route requires a login; startup fails deliberately if no account
exists and `ADMIN_PASSWORD` is unset, because that would lock the deployment out.

**Gotcha:** `postgres_host` defaults to `postgres`, which only resolves inside the compose
network. Running uvicorn on the host needs `POSTGRES_HOST=localhost` plus a published
Postgres port (compose deliberately does not publish one), or `POSTGRES_DSN_OVERRIDE`.

## Tests, lint, format

```bash
pip install -r requirements-dev.txt   # pytest + ruff
pytest              # tests/
ruff format .
ruff check .
```

The runtime dependencies are pinned in `requirements-lock.txt`. To regenerate it
after changing `requirements.txt`:

```bash
python -m venv /tmp/lock-env
/tmp/lock-env/bin/pip install -r requirements.txt
/tmp/lock-env/bin/pip freeze > requirements-lock.txt
rm -rf /tmp/lock-env
```

Docker builds use `requirements-lock.txt`.

ruff is configured in `pyproject.toml`: line-length 100, target py311, rules `E,F,I,B`.
The `UP` (pyupgrade) rules are deliberately off — this codebase uses `Optional[X]` and
`typing.Dict` style, and modernizing it is not in scope. Keep matching that style.
A PostToolUse hook runs `ruff format` on each Python file you edit.

## Deliberate design constraints

- Every route requires authentication. There is no anonymous view.
- Routes that modify configuration, integrations, passwords, or that trigger an ingest
  require the `admin` role (`require_admin`). Read-only users are supported at the schema
  level even though the UI currently creates only admins on first run.
- `/vulnerabilities/summary` and `/vulnerabilities/cves` must keep sharing the
  `_vuln_rows` / `_apply_vuln_filters` helpers in `app/main.py` so KPIs and the table
  never desync. New filtering logic goes in those helpers, not in one route.
- `/vulnerabilities/cves` also **sorts** server-side (`_sort_rows`), because it paginates
  server-side: sorting in the browser would only reorder the ten rows already on screen.
  A new sortable column needs an entry in `_SORTABLE` and one in `COLS` in `index.html`.
- The dashboard mirrors its filters, sort and page into the query string (`syncUrl` /
  `readUrl` in `index.html`) so a filtered view can be shared. It uses `replaceState`: the
  search box fires on every keystroke, and `pushState` would make each letter a history entry.
- Filtering and aggregation happen in Python over the cached JSONB state in
  `vuln_state_cache` (a single row, `CHECK (id = 1)`) — not in SQL. Only the
  lifecycle/SLA metrics (`patching_metrics`) are real queries.
- `app/wazuh/manager.py` is the **only** code that writes to Wazuh, and it does exactly one
  thing: restart named agents so they re-inventory themselves (Wazuh 4.8+ has no on-demand
  vulnerability scan). It is optional — with no manager API configured the app is strictly
  read-only — admin-only, never accepts "all agents", and always refuses agent `000`.
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
- The side menu lives in `static/_sidebar.html` — one copy for the whole panel. `app/pages.py`
  splices it into any page containing `<!--sidebar-->`, so the page routes return
  `HTMLResponse(render_page(...))`, not `FileResponse`. `login`/`signup` carry no marker and
  stay bare. **Menu styling goes in `sidebar.css`**, never in a page's inline `<style>`: that
  is how the menu came out lime and icon-less on every screen but the dashboard.
- Stylesheet order is `tailwind.css` *then* `theme.css`. theme.css reassigns tailwind's
  `--color-*` tokens and only wins by source order — swapping the two links puts the frozen
  build's blue-and-lime brand back.
- `theme.css` carries both themes: `:root` is light, `[data-theme="dark"]` is dark. A new
  `--pg-*` token needs a value in **both** blocks — one defined on a single side silently
  inherits the other theme's value, which is how the light theme ended up rendering dark
  panels. Page CSS reaches for `--pg-*`, never tailwind's dark greys (`--color-gray-dark`,
  `--color-gray-800`): those are remapped only under `[data-theme="dark"]` and fall back to
  near-black in light.
- Theme is applied pre-paint by `theme-preload.js` — a blocking `<head>` script — and
  re-applied in `theme.js`. **Every page must load both**, or it ignores the chosen theme.
  localStorage keys: `soc.theme` (`light`|`soc`), `soc.navCollapsed`.

## Conventions

- Existing code, comments and docstrings are Spanish; **write new comments, docstrings,
  docs and commit messages in English.** Do not mass-translate existing Spanish comments.
- **Everything the user reads is English**: labels, table headers, badges, placeholders,
  tooltips, `confirm`/`alert` text and the `detail` of any HTTPException that reaches a
  screen.
- Spanish stays where it is a **data contract**, never prose: API field names (`severidad`,
  `dias_detectado`, `criticas_altas`) and DB status values (`pendiente`, `en_curso`,
  `parcial`, `resuelto`, `aceptado_riesgo`). Those keys are rendered through
  `ESTADO_LABEL` in `index.html` — translate the label, never the key.
- The panel ships English-only. `i18n.js` keeps the machinery and an empty `DICT.es`; the
  `lang` setting still picks the language the AI brief is written in.
- Every module starts with `from __future__ import annotations`. Type hints throughout.
- Never commit to `master`. Branch, then open a PR with `gh`.
