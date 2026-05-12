#!/bin/bash
# OpenHost entrypoint for FreshRSS.
#
# Topology:
#
#   [router] --8080--> [auth_proxy.py] --8800--> [apache + FreshRSS]
#
# We shim the upstream apache port from 80 to 8800 via LISTEN env
# so the auth-proxy can bind 8080 unprivileged.  Then we run the
# upstream entrypoint in the background (it idempotently runs
# do-install.php via FRESHRSS_INSTALL on first boot, so we don't
# need a separate bootstrap script), and start the auth-proxy in
# the foreground.

set -euo pipefail

# Repoint FreshRSS' data dir at OpenHost's persistent volume so it
# survives reload + redeploy.  FreshRSS reads /var/www/FreshRSS/data
# by default; we'd rather store everything under
# $OPENHOST_APP_DATA_DIR for consistency with other apps.
DATA_DIR="${OPENHOST_APP_DATA_DIR:-/var/www/FreshRSS/data}"
mkdir -p "${DATA_DIR}"

# Replace FreshRSS' built-in data dir with a symlink to our
# persistent location BEFORE the upstream entrypoint runs.
# Otherwise it'll write applied_migrations.txt + config.php to
# the ephemeral container path.
if [ -d /var/www/FreshRSS/data ] && [ ! -L /var/www/FreshRSS/data ]; then
    if [ -n "$(ls -A /var/www/FreshRSS/data 2>/dev/null || true)" ]; then
        cp -a /var/www/FreshRSS/data/. "${DATA_DIR}/" || true
    fi
    rm -rf /var/www/FreshRSS/data
fi
if [ ! -L /var/www/FreshRSS/data ]; then
    ln -s "${DATA_DIR}" /var/www/FreshRSS/data
fi

# Apache shimmed to bind only on the auth-proxy's upstream port
# (loopback).  127.0.0.1:8800 keeps it unreachable from outside
# the container and lets the auth-proxy own 8080.
export LISTEN="127.0.0.1:8800"

# Trust the loopback auth-proxy as the upstream IP source.
# Apache's mod_remoteip + FreshRSS use this to extract the real
# client IP from X-Forwarded-For.
export TRUSTED_PROXY="127.0.0.1/32"

# Schedule a feed refresh every 15 minutes.  CRON_MIN goes into
# the upstream image's crontab via entrypoint.sh.
export CRON_MIN="${CRON_MIN:-*/15}"

# FRESHRSS_INSTALL: the upstream entrypoint passes this as args
# to ``cli/do-install.php`` on every boot.  do-install bails with
# exit 3 ("already installed") on subsequent boots — that's the
# documented idempotency hook, so we don't need a separate
# bootstrap script.
#
# Critical flags:
#   * --auth-type http_auth   — read $_SERVER['HTTP_X_WEBAUTH_USER']
#                               on every request as the authenticated
#                               user.  The auth-proxy stamps this
#                               header on owner requests.
#   * --default-user admin    — must match what auth_proxy.py stamps
#                               (AUTH_PROXY_OWNER_USERNAME).
#   * --db-type sqlite        — zero-config DB.
#   * --disable-update true   — Docker installs upgrade via image
#                               pulls, not in-app self-update.
#   * --api-enabled true      — exposes the FreshRSS native + Fever
#                               + Google Reader APIs for third-party
#                               clients.  Mobile readers use this.
export FRESHRSS_INSTALL="--default-user admin --auth-type http_auth --db-type sqlite --language en --title 'FreshRSS-on-OpenHost' --api-enabled true --disable-update true"

# Launch the auth-proxy in the foreground; background the
# upstream entrypoint.
echo "[start] launching upstream FreshRSS entrypoint..." >&2
(
    # Hand control to the upstream image's standard boot — it
    # handles apache config, install, cron + finally exec's
    # apache2.  We pass the apache CMD verbatim from the upstream
    # Dockerfile.
    cd /var/www/FreshRSS && exec /var/www/FreshRSS/Docker/entrypoint.sh \
        sh -c '([ -z "$CRON_MIN" ] || cron) && . /etc/apache2/envvars && exec apache2 -D FOREGROUND'
) &
UPSTREAM_PID=$!

# Wait for apache to come up on the loopback shim port (max 90s).
echo "[start] waiting for apache on 127.0.0.1:8800..." >&2
for _ in $(seq 1 90); do
    if (echo >/dev/tcp/127.0.0.1/8800) 2>/dev/null; then
        echo "[start] apache reachable on 127.0.0.1:8800" >&2
        break
    fi
    if ! kill -0 "$UPSTREAM_PID" 2>/dev/null; then
        echo "[start] upstream FreshRSS entrypoint died before apache came up" >&2
        wait "$UPSTREAM_PID" || true
        exit 1
    fi
    sleep 1
done

# Launch the OpenHost auth-proxy on :8080.  Stamps X-WebAuth-User
# on owner requests, passes everything else through unchanged.
echo "[start] launching auth_proxy.py on 0.0.0.0:8080..." >&2

trap 'kill -TERM "$UPSTREAM_PID" 2>/dev/null; wait' TERM INT

set +e
python3 /opt/auth_proxy.py &
PROXY_PID=$!
wait -n "$UPSTREAM_PID" "$PROXY_PID"
EXIT_CODE=$?
set -e

echo "[start] child exited (code=$EXIT_CODE); shutting down" >&2
kill -TERM "$UPSTREAM_PID" "$PROXY_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
