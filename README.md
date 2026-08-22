# Vulnerability & Patch Tracking — Demo

Pantalla de seguimiento de vulnerabilidades (SLA de parcheo, priorización
CVSS/EPSS/KEV, asignación de responsables) extraída de un panel SOC L1
productivo, para mostrarla como demo pública.

**Todos los datos son sintéticos.** Ningún CVE, servidor o paquete listado
corresponde a infraestructura real, salvo un puñado de CVEs públicos de alto
perfil (Log4Shell, PrintNightmare, Citrix Bleed, Zerologon) usados solo como
ejemplo de cómo se ve una alerta de CISA KEV / ransomware conocido — son
vulnerabilidades de dominio público, no información de ningún cliente.

## Qué hace

- Prioriza CVEs con el mismo criterio que un panel SOC real: **CISA KEV**
  (explotación activa confirmada) primero, **EPSS** (probabilidad de
  explotación a 30 días) después, y un **score de prioridad** ponderado
  (`CVSS·peso + EPSS·peso + bonus si está en KEV`).
- Calcula SLA de parcheo de críticas, aging, altas/resueltas de los últimos
  7 días, todo desde un ciclo de vida por CVE guardado en Postgres.
- Permite asignar responsable/estado/fecha objetivo a cada CVE (sin
  autenticación: cualquier visitante puede crear o borrar asignaciones —
  ver [Notas de la demo](#notas-de-la-demo)).
- Gráficos de evolución, distribución por severidad, top paquetes y
  distribución por servidor (ApexCharts, vendorizado, sin CDN).

## Correr localmente

```bash
cp .env.example .env
docker compose up --build
```

Abrí `http://localhost:8000`. La primera vez que levanta, el contenedor de la
API siembra la base con datos sintéticos automáticamente (`seed/generate_seed.py`)
— no hace falta ningún paso manual.

## Estructura

```
app/          FastAPI: rutas de lectura/seguimiento, sin autenticación
seed/         Generador de datos sintéticos (CVEs, snapshots, asignaciones)
static/       Frontend (HTML/CSS/JS vanilla + ApexCharts vendorizado)
deploy/       nginx + notas para desplegar en un VPS propio
```

## Notas de la demo

- **Sin autenticación.** El backend original tiene login (Entra ID / Basic)
  y auditoría; se sacaron para esta demo pública. Cualquiera puede crear o
  borrar asignaciones de seguimiento vía la UI o la API.
- **Reset periódico recomendado.** Para que la demo no degrade con el tiempo,
  conviene correr `python -m seed.generate_seed --reset --yes` con un cron
  (ver `deploy/DEPLOY.md`), que vacía y vuelve a sembrar los datos.
- **Sin Wazuh/EPSS/CISA en vivo.** El endpoint de refresh manual del sistema
  original no existe acá — los datos son estáticos entre resets.
- **Origen.** Este repo es un extracto de un panel SOC L1 productivo
  (Postgres + FastAPI + Wazuh), reescrito para no depender de ninguna
  infraestructura ni dato de cliente real.

## Licencia

MIT — ver [LICENSE](LICENSE).
