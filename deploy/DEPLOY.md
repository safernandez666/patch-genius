# Deploy en un VPS propio

Pasos manuales — ejecutar uno por uno, con el DNS del subdominio ya apuntando
al VPS antes de pedir el certificado.

1. **Clonar el repo en el VPS**
   ```bash
   git clone <url-del-repo> patch-genius
   cd patch-genius
   ./scripts/setup-env.sh   # genera .env con APP_SECRET_KEY y ADMIN_PASSWORD
   ```

2. **Levantar los containers**
   ```bash
   docker compose up -d --build
   curl -s localhost:8000/api/setup-state   # debe devolver {"needs_setup":false} tras el primer login
   ```

3. **nginx + certbot** (el VPS ya debe tener nginx instalado)
   ```bash
   sudo cp deploy/nginx.conf.example /etc/nginx/sites-available/patch-genius
   # editar server_name en ese archivo antes de habilitarlo
   sudo ln -s /etc/nginx/sites-available/patch-genius /etc/nginx/sites-enabled/
   sudo nginx -t && sudo systemctl reload nginx
   sudo certbot --nginx -d patch.tu-dominio.com
   ```

4. **Actualizar tras un cambio en el repo**
   ```bash
   git pull
   docker compose up -d --build
   ```

## Certificado

Si el VPS ya tiene un wildcard existente, se puede reusar en vez de pedir uno
nuevo con certbot — solo hay que apuntar `ssl_certificate`/`ssl_certificate_key`
a esos archivos en el `nginx.conf` de este subdominio.
