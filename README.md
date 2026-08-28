<div align="center">

<img src="static/assets/genie.svg" alt="" align="center" height="120" />

# Patch Genius

**Vulnerability and patch tracking on top of your own Wazuh.**

[![License](https://img.shields.io/badge/License-MIT-76ABAE?style=flat-square)](LICENSE)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.8+-303841?style=flat-square)](https://wazuh.com)
![Python](https://img.shields.io/badge/Python-3.11-303841?style=flat-square)
![Postgres](https://img.shields.io/badge/Postgres-15-303841?style=flat-square)
[![Zebra Security](https://img.shields.io/badge/by-Zebra_Security-FF5722?style=flat-square)](https://zebrasecurity.io)

[Overview](#overview) • [Features](#features) • [How it works](#how-it-works) • [Get started](#get-started) • [Security](#security) • [FAQ](#faq)

![Dashboard](docs/img/dashboard.png)

</div>

Wazuh tells you **what** is unpatched. It does not tell you what to patch **first**, how
long it has been that way, or who owns it. Patch Genius reads the vulnerability state out
of your Wazuh Indexer, ranks it the way an analyst would, and tracks remediation per CVE
and per agent.

> [!IMPORTANT]
> There is no sample data and no demo mode. The dashboard shows what the Wazuh you
> configure reports, or nothing at all.

## Overview

Wazuh 4.8 moved vulnerability data out of the manager API and into the indexer, so
`wazuh-states-vulnerabilities-*` is the only supported source. That index holds
**currently active vulnerabilities only** — a record is deleted the moment a package is
patched, and there is no status field and no history.

Everything the dashboard shows about time is therefore derived here, not read from Wazuh:

- **Resolved and reopened** come from diffing each ingest against the previous one.
- **Aging and SLA** run on a first-seen date this app records itself. Wazuh rewrites
  `vulnerability.detected_at` whenever it re-indexes a record, so a clock built on that
  field silently restarts and never breaches.

## Features

- **Ranked the way an analyst would** — CISA KEV first (confirmed exploitation in the
  wild), EPSS next (probability of exploitation within 30 days), then a single weighted
  score to sort by: `CVSS·w + EPSS·w + KEV bonus`.
- **Linux and Windows kept apart** — an OS-level finding closes with a cumulative update
  or KB, not with `apt`. A single Windows build can carry thousands of CVEs, so those are
  summarised separately instead of flattening every real package out of the ranking.
- **Untriaged CVEs kept visible** — Wazuh reports unscored CVEs with severity `-` and the
  sentinel score `-1.0`. They get their own bucket rather than being dropped or ranked as
  a genuine zero: unscored means unknown, not harmless.
- **Ownership per CVE and per agent** — the same CVE can be resolved on one host and open
  on another, so owner, status and due date are tracked at that granularity.
- **A brief that says what to do** — an LLM turns the ranking into a paragraph naming the
  packages to patch first, written on demand. Claude, OpenAI, or a local model: hostnames
  are included by default because that is what makes it actionable, and a single switch
  strips them. Anyone who cannot send that inventory out points it at their own endpoint
  and nothing leaves.
- **Onboarding in the app** — the Wazuh connection is configured from a tab, tested before
  it is saved, and stored encrypted. Nothing is baked into the image.
- **Proof that the patching is working** — a Health check screen that only looks backwards:
  what closed, on which server, how long each CVE had been open, and when each patch landed.
  Reopened CVEs are called out separately, because a closure that comes back is the one
  thing a "resolved" counter will never tell you.
- **Check a patch without waiting for the next cycle** — *Refresh now* re-reads the indexer
  on the spot, and *Force rescan* restarts the agents you pick so Wazuh re-inventories them
  and the CVEs you just closed drop off. The second one is optional and needs the manager
  API; without it the app never writes to Wazuh.
- **English or Spanish** — set once for the installation, since a SOC screen is read by the
  whole team.
- **No build step** — clone, `docker compose up`. No Node, no CDN, no external asset
  fetches, which matters on isolated networks.

## How it works

[![Architecture](docs/img/arquitectura.png)](docs/diagrams/architecture.html)

<sub>Open [`docs/diagrams/architecture.html`](docs/diagrams/architecture.html) for the
interactive version — guided views, relationship tracing, light/dark and export.</sub>

> [!NOTE]
> The public feeds are queried **by CVE identifier only** — nothing about your
> infrastructure leaves the network. The KEV catalog is cached in Postgres for six hours,
> so a normal ingest does not call CISA at all, and a fetch that fails falls back to the
> last catalog it held. On an air-gapped host, turn the feeds off and scoring degrades to
> CVSS alone.

A single ingest:

[![One ingest run](docs/img/ingesta.png)](docs/diagrams/ingest.html)

<sub>Interactive: [`docs/diagrams/ingest.html`](docs/diagrams/ingest.html)</sub>

## Get started

You need **Wazuh 4.8 or newer**, network access to its Indexer on port 9200, and Docker
with Docker Compose.

```bash
git clone https://github.com/safernandez666/patch-genius.git
cd patch-genius
./scripts/setup-env.sh
docker compose up -d --build
```

`setup-env.sh` generates `.env` with a fresh encryption key and a random admin password,
and prints the credentials. Skip it and the sign-up screen creates the first account
instead — it answers only while no account exists and closes itself the moment one does, so
it never becomes an open registration form.

### Open it from other machines on the LAN

Out of the box Docker publishes port 8000 on loopback only, so the panel answers at
`http://localhost:8000` on the host and nowhere else. To let the rest of the network in,
set the interface to publish on in `.env` and recreate the container:

```bash
echo 'APP_BIND=0.0.0.0' >> .env      # or a specific address, e.g. 192.168.1.10
docker compose up -d
```

The panel is then at `http://<host-lan-ip>:8000` for anyone on the network. Nothing else
has to change: the frontend is served from the same origin, so `CORS_ORIGINS` stays empty,
and the session cookie works over plain HTTP.

Two things to keep in mind:

- **Docker writes its own iptables rules on Linux**, so a published port bypasses `ufw`
  allow/deny rules. Restrict it at the source instead — `APP_BIND=192.168.1.10` publishes
  on that interface only — or add the rule to the `DOCKER-USER` chain.
- **Traffic is unencrypted**, including the login. That is usually fine inside a trusted
  LAN; for anything wider, leave `APP_BIND` on loopback and put the nginx + TLS setup in
  [`deploy/`](deploy/DEPLOY.md) in front instead.

### Reset the database

The first time you start the stack the database is already blank — you do **not** need to
run this script on a fresh clone.

Use it only when you want to wipe local data and start over, or when you changed
`POSTGRES_PASSWORD` in `.env` after the Postgres volume was already created (Postgres keeps
the original password in the volume, so the API will fail to authenticate until you reset):

```bash
./scripts/reset-db.sh
```

It stops the containers, deletes the Postgres Docker volume, rebuilds the API image, and
brings everything back up. Use `./scripts/reset-db.sh --yes` to skip the confirmation
prompt — useful in CI or fresh installs.

### Connect Wazuh

Patch Genius reads vulnerability state from your Wazuh Indexer. After the stack is up,
open the **Configuration** tab and fill in the Indexer connection.

#### 1. Make the Indexer reachable

| Topology | What you need |
|---|---|
| Patch Genius on the same host as Wazuh | Nothing. Use `https://127.0.0.1:9200`. |
| Patch Genius on a different host | Expose port `9200` on the Wazuh host (see firewall note below). |
| You prefer not to expose 9200 | Use an SSH tunnel: `ssh -N -L 9200:127.0.0.1:9200 root@<wazuh-host>` and point the app at `https://127.0.0.1:9200`. |

A default Wazuh install binds the Indexer to `127.0.0.1`, so other hosts cannot reach it.
Binding to `0.0.0.0` switches OpenSearch to production mode and requires bootstrap checks
(`vm.max_map_count >= 262144`, file descriptors, etc.). If you go this route, firewall port
`9200` to the app host only — it holds your whole vulnerability inventory.

#### 2. Create a read-only Indexer user

Do **not** use the Wazuh `admin` account. In the Wazuh dashboard, create an internal user
and role with:

- Cluster permissions: `cluster_composite_ops_ro`
- Index patterns: `wazuh-states-vulnerabilities-*` and `wazuh-states-inventory-*`
- Index permissions: `read`

#### 3. Save the connection in the app

In **Configuration → Wazuh**:

| Field | Example | Notes |
|---|---|---|
| Indexer URL | `https://wazuh.example.com:9200` | Use `127.0.0.1` for same-host or tunnel setups |
| Username / password | read-only user from Step 2 | Stored encrypted; never written to the repo |
| Verify TLS | off for default install | Wazuh ships self-signed certs |
| Manager API URL / user / password | `https://<wazuh-host>:55000` | Optional — only for the **Force rescan** button |

Press **Test connection**. A green result means the app can see the cluster and the
vulnerability documents. Save, then run the first ingest from the dashboard.

> For the full checklist — bootstrap checks, rollback steps, TLS details, and the manager
> API role for Force rescan — see [`docs/ONBOARDING.md`](docs/ONBOARDING.md).

![Sign in](docs/img/login.png)

### Integrations

Wazuh, SMTP, Jira, Slack and Microsoft Teams are configured from one page.

![Integrations](docs/img/integraciones.png)

**Test** exercises the real thing — it authenticates against the indexer, sends the mail,
posts to the channel — because a saved setting that was never tried tells you nothing.
Credentials are encrypted at rest and never returned to the browser; a webhook URL counts
as one, since anyone holding it can post into your channel.

### After you patch

The dashboard re-reads the indexer on a schedule, so a machine you patched five minutes ago
still shows its old CVEs. Two buttons sit above the KPIs for that:

- **Refresh now** re-runs the ingest against the Indexer immediately. Enough when Wazuh has
  already re-scanned the host.
- **Force rescan** picks agents and restarts them through the manager API. Wazuh 4.8+ has
  no on-demand vulnerability scan — detection is event-driven — so restarting the agent is
  the supported trigger: it re-runs syscollector on start, ships a fresh package list, and
  the manager re-evaluates it. The ingest that reads the result is scheduled a few minutes
  out (`WAZUH_RESCAN_DELAY_SECONDS`, default 180) and the page updates itself when it
  lands.

> [!WARNING]
> Force rescan restarts the Wazuh agent on real machines. It is the only place this app
> writes to Wazuh, it is admin-only, agents are always named explicitly (never "all"),
> agent `000` — the manager — is refused, and a single request is capped at
> `WAZUH_RESCAN_MAX_AGENTS` (default 25). Leave the manager API unconfigured and the
> feature stays off; everything else keeps working read-only.

The manager account needs `agent:restart` on the agents you intend to rescan — not `admin`.

### Did it actually get fixed

`/health` in the sidebar. Every other screen answers "what is open"; this one answers whether
the fleet is getting better, and it is the only view built from the lifecycle table rather than
the live state — Wazuh deletes a record the moment the package is patched, so a closure exists
nowhere else.

- **Indicators** for the window you pick (7/30/90/180 days): closures, unique CVEs, servers,
  median time to patch, share of criticals closed inside the SLA, and reopened count.
- **Patching activity** — closures per day, by the severity the CVE carried when it closed.
- **When each patch landed** — one bar per batch, meaning everything a server closed on the
  same day. It runs from the oldest CVE in the batch to the day it closed, so the length is the
  debt the host was carrying and the right edge is the patch window. A bar per CVE was the first
  attempt and it is unreadable: a Windows box closes hundreds on the same day.
- **By server** — closed against what the host still carries. A server that closes a lot and
  still holds hundreds is not healthy, and a leaderboard of closures alone would rank it first.

Everything is counted per (CVE, server) pair, like the rest of the lifecycle metrics: closing a
CVE on one of five hosts is one fifth of the work, not all of it.

### What to prioritise

The ranking answers "which CVE is worst". This answers "what do I do on Monday" — written
on demand, from the dashboard or from this page.

![What to prioritise](docs/img/brief.png)

> [!WARNING]
> The brief is built from the fleet's real state, hostnames included — that is what makes
> it specific enough to act on. With a hosted model that inventory leaves your network.
> Turn off **Include server hostnames** and the model sees host counts instead of names, or
> point it at a local OpenAI-compatible endpoint and nothing leaves at all. It ships
> disabled.

### Configuration

Everything about this installation rather than a connection: how often the indexer is
re-read, which language the interface uses, whether the public feeds are enabled, and the
password.

![Configuration](docs/img/configuracion.png)

> [!WARNING]
> A default Wazuh install binds the Indexer to `127.0.0.1` only. If Patch Genius runs on a
> different host you must either expose port 9200 or tunnel to it — and exposing it
> switches OpenSearch into production mode, where failed bootstrap checks stop the service
> from starting. [docs/ONBOARDING.md](docs/ONBOARDING.md) covers the preconditions to
> verify first, and how to roll back.

The app explains its own scoring, lifecycle and SLA rules at `/ayuda`:

![Help](docs/img/ayuda.png)

## Security

This dashboard is an inventory of what is unpatched on live machines, and the
configuration holds Wazuh credentials. Both are treated accordingly.

- **Every route requires a login.** There is no anonymous view.
- **Credentials are encrypted at rest** with Fernet, using `APP_SECRET_KEY`, which never
  reaches the database or the repository. They are never returned to the browser.
- **Use a read-only Indexer account**, not `admin`. ONBOARDING walks through creating one
  scoped to `wazuh-states-*` with `cluster_composite_ops_ro`.
- **Configuration is admin-only.** Integrations, the password, the app settings, the manual
  ingest and the forced rescan all require the `admin` role, not merely a session.
- **The only write to Wazuh is an agent restart**, it is opt-in (leave the manager API
  blank and it does not exist), rate limited to 6 requests a minute, and never applies to
  the manager itself.
- **Sign-in is rate limited** — 10 attempts a minute per IP, 5 for the first-run sign-up.
- **The container runs as an unprivileged user** and declares a healthcheck; runtime
  dependencies are pinned in `requirements-lock.txt`, which is what the image installs.
- **Change the bootstrap password** from the configuration tab after signing in.

## FAQ

**Why are the trend charts empty on day one?**
Wazuh keeps no history, so the series is built forward from your first ingest — one
snapshot per day. Aging is 0 for everything until the app has been running a while.

**Why does the platform breakdown add up to more than the CVE count?**
A CVE present on both a Debian box and a Windows one is genuinely open in two places, so
it is counted under both.

**Can it read from something other than Wazuh?**
Not yet, but the collector is the only Wazuh-specific part. `app/ingest.py:collect()`
dispatches on the configured scanner, and everything downstream consumes a normalised
record shape, so adding another source means writing one collector.

**Does anything of mine reach the model?**
Only if you enable the brief and choose a hosted provider. It sends the fleet snapshot —
severity counts, platform split, patching metrics, and the top 25 CVEs with their hosts and
packages. Turning off **Include server hostnames** replaces the names with a count; a local
endpoint keeps all of it inside your network. EPSS and CISA KEV are separate and only ever
see CVE identifiers.

**Where do I change the scoring weights?**
Environment variables — `VULN_CVSS_WEIGHT`, `VULN_EPSS_WEIGHT`, `VULN_KEV_WEIGHT`,
`VULN_SLA_CRITICAL_DAYS` and friends. See `app/settings.py`.

---

<div align="center">
<sub>Built by <a href="https://zebrasecurity.io"><b>Zebra Security</b></a></sub>
</div>
