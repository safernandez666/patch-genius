#!/usr/bin/env sh
# Generate a .env with fresh secrets. Run once, before the first `docker compose up`.
set -eu

cd "$(dirname "$0")/.."

if [ -f .env ]; then
  echo ".env already exists — refusing to overwrite it." >&2
  echo "Delete it first if you really want to regenerate the secrets." >&2
  echo "Note: regenerating APP_SECRET_KEY makes the stored Wazuh password" >&2
  echo "unreadable, and it has to be re-entered in the Configuration tab." >&2
  exit 1
fi

gen() { python3 -c "import secrets;print(secrets.token_urlsafe($1))"; }
fernet() { python3 -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"; }

ADMIN_PASSWORD=$(gen 18)

cat > .env <<ENVEOF
POSTGRES_USER=vulndemo
POSTGRES_PASSWORD=$(gen 16)
POSTGRES_DB=vulndemo

APP_SECRET_KEY=$(fernet)

ADMIN_USER=admin
ADMIN_PASSWORD=$ADMIN_PASSWORD

CORS_ORIGINS=
ENVEOF

chmod 600 .env
echo "Wrote .env"
echo
echo "  Sign in with:  admin / $ADMIN_PASSWORD"
echo
echo "Change it from the Configuration tab after your first sign-in."
