# Patch Genius

Seguimiento de vulnerabilidades y parcheo sobre datos de **tu propio Wazuh**:
prioriza CVEs con CISA KEV y EPSS, calcula SLA de parcheo y aging, y permite
asignar responsable, estado y fecha objetivo por CVE.

Extraído de un panel SOC productivo y reescrito para que cualquiera lo apunte a
su instalación. **No trae datos de ejemplo**: muestra lo que reporta el Wazuh que
configures, o nada.

## Qué hace

- Lee el índice `wazuh-states-vulnerabilities-*` del Wazuh Indexer (4.8 o
  superior — en 4.8 los datos salieron de la API del manager al indexer).
- Prioriza con el mismo criterio que un panel SOC: **CISA KEV** (explotación
  activa confirmada) primero, **EPSS** (probabilidad de explotación a 30 días)
  después, y un **score ponderado** (`CVSS·peso + EPSS·peso + bonus si KEV`).
- Separa **Linux y Windows**: los hallazgos a nivel sistema operativo se cierran
  con una actualización acumulativa o KB, no actualizando un paquete, así que van
  aparte del ranking de paquetes.
- Calcula **aging y SLA con fecha propia**. Wazuh reescribe
  `vulnerability.detected_at` cada vez que reindexa un registro, así que un reloj
  basado en ese campo se reinicia solo y nunca vence.
- Deriva **resuelto y reabierto** comparando cada ingesta con la anterior: el
  índice de Wazuh solo contiene vulnerabilidades activas y borra el registro
  cuando el paquete se parchea.

## Requisitos

- Wazuh **4.8+** y acceso de red al Indexer (puerto 9200).
- Docker y Docker Compose.

## Instalación

```bash
./scripts/setup-env.sh     # genera .env con secretos nuevos e imprime tu contraseña
docker compose up -d --build
```

Abrí `http://localhost:8000`, ingresá con las credenciales que imprimió el
script, y conectá tu Wazuh desde la pestaña **Configuración**.

Si el Indexer solo escucha en `127.0.0.1` y esta app corre en otro host, leé
primero **[docs/ONBOARDING.md](docs/ONBOARDING.md)** — es el paso donde se traba
la mayoría.

## Seguridad

- **Todas las rutas requieren login.** La pantalla lista los CVEs sin parchear de
  máquinas vivas; no hay modo abierto.
- Las credenciales de Wazuh se guardan **cifradas** (Fernet) con la llave de
  `APP_SECRET_KEY`, que nunca va a la base ni al repositorio, y **no se devuelven
  al navegador**.
- Usá un **usuario de solo lectura** del Indexer, no `admin` — ver ONBOARDING.
- Cambiá la contraseña inicial desde Configuración después del primer ingreso.

## Estructura

```
app/          FastAPI: rutas, ingesta, scoring, auth y configuración
app/wazuh/    Cliente del Indexer y mapeo a la vista por CVE
static/       Frontend (HTML/CSS/JS vanilla + ApexCharts vendorizado)
docs/         Onboarding de Wazuh
deploy/       nginx + notas para desplegar en un VPS propio
```

## Licencia

MIT — ver [LICENSE](LICENSE). Los assets de terceros tienen su propia licencia:
ver [static/assets/CREDITS.md](static/assets/CREDITS.md).
