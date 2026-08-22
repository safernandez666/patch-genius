---
name: reseed
description: Wipe and regenerate the synthetic demo data for the vulnerability tracker. Destructive — truncates all vuln tables and reseeds from seed/generate_seed.py.
disable-model-invocation: true
---

# Reseed the demo database

Regenerates the synthetic CVE / snapshot / assignment data. **This is destructive** — it
truncates the `vuln_*` tables and rebuilds them from scratch, discarding any assignments
visitors created.

Arguments: $ARGUMENTS (optional — pass `host` to run against a local Postgres instead of
the compose container).

## Steps

1. Confirm with the user before running. Say exactly what will be lost: all owner/status
   assignments made through the UI since the last reseed.

2. Check the stack is up:

   ```bash
   docker compose ps
   ```

   If the `api` and `postgres` services aren't running, tell the user and stop — don't
   start them silently.

3. Run the reseed inside the api container (the default path):

   ```bash
   docker compose exec -T api python -m seed.generate_seed --reset --yes
   ```

   If `$ARGUMENTS` is `host`, run it locally instead — this needs a reachable Postgres,
   which compose does not publish by default, so it requires `POSTGRES_HOST=localhost`
   plus a published port, or `POSTGRES_DSN_OVERRIDE`:

   ```bash
   POSTGRES_HOST=localhost python -m seed.generate_seed --reset --yes
   ```

4. Verify the API came back with data:

   ```bash
   curl -s localhost:8000/healthz
   curl -s localhost:8000/vulnerabilities/summary | head -c 400
   ```

5. Report the CVE count and whether the summary endpoint returned non-empty KPIs. If the
   summary is empty, check `docker compose logs api` for a `vuln_tables_init_failed`
   warning — schema errors surface as empty data, not as crashes.

## Notes

- `--reset` requires `--yes`; the script refuses to truncate without it.
- The seed is deterministic (`SEED = 20260822` in `seed/generate_seed.py`), so a reseed
  reproduces the same dataset unless that constant changed.
- Without `--reset`, the script is a no-op when data already exists (`seed_if_empty`).
