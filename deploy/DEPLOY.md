# Deploy en un VPS propio

Pasos manuales — ejecutar uno por uno, con el DNS del subdominio ya apuntando
al VPS antes de pedir el certificado.

1. **Clonar el repo en el VPS**
   ```bash
   git clone <url-del-repo> vuln-patch-tracker-demo
   cd vuln-patch-tracker-demo
   cp .env.example .env   # editar la clave de Postgres
   ```

2. **Levantar los containers**
   ```bash
   docker compose up -d --build
   curl -s localhost:8000/healthz   # debe devolver {"status":"ok"}
   ```

3. **nginx + certbot** (el VPS ya debe tener nginx instalado)
   ```bash
   sudo cp deploy/nginx.conf.example /etc/nginx/sites-available/vulndemo
   # editar server_name en ese archivo antes de habilitarlo
   sudo ln -s /etc/nginx/sites-available/vulndemo /etc/nginx/sites-enabled/
   sudo nginx -t && sudo systemctl reload nginx
   sudo certbot --nginx -d demo.tu-dominio.com
   ```

4. **Reset periódico de los datos** (recomendado — la demo es pública y sin
   auth, cualquiera puede editar/borrar asignaciones). Cron diario a las 4am:
   ```cron
   0 4 * * * cd /ruta/a/vuln-patch-tracker-demo && docker compose exec -T api python -m seed.generate_seed --reset --yes >> /var/log/vulndemo-reset.log 2>&1
   ```

5. **Actualizar la demo tras un cambio en el repo**
   ```bash
   git pull
   docker compose up -d --build
   ```

## Certificado

Si el VPS ya tiene un wildcard existente (como el que usa `wazuhprd`), se
puede reusar en vez de pedir uno nuevo con certbot — solo hay que apuntar
`ssl_certificate`/`ssl_certificate_key` a esos archivos en el `nginx.conf`
de este subdominio.
