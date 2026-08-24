#!/usr/bin/env sh
# Reset the local Postgres database to a blank state.
# This destroys all data in the Docker volume and recreates the stack.
set -eu

cd "$(dirname "$0")/.."

confirm() {
  if [ "${1:-}" = "--yes" ] || [ "${1:-}" = "-y" ]; then
    return 0
  fi
  printf "This will DELETE all local data in the patch-tracker Postgres volume. Continue? [y/N] "
  read -r answer
  case "$answer" in
    [Yy]*) return 0 ;;
    *) echo "Aborted."; exit 0 ;;
  esac
}

confirm "${1:-}"

echo "Stopping containers and removing the Postgres volume..."
docker compose down -v

echo "Rebuilding and starting the stack..."
docker compose up -d --build

echo "Waiting for services to be healthy..."
attempts=0
max_attempts=30
while [ $attempts -lt $max_attempts ]; do
  if docker compose ps | grep -q "healthy"; then
    echo
    docker compose ps
    echo
    echo "Stack is up. The database is now blank."
    exit 0
  fi
  attempts=$((attempts + 1))
  sleep 2
done

echo "Timed out waiting for services to become healthy. Check the logs with:"
echo "  docker compose logs"
exit 1
