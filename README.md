# openhost-freshrss

[FreshRSS](https://www.freshrss.org/) packaged for OpenHost with
**one-click SSO** for the zone owner.

## What it is

A self-hosted RSS / Atom feed aggregator.  Web UI for reading
feeds, mobile-friendly, supports OPML import/export, Fever API,
Google Reader API, and the FreshRSS native API for third-party
clients (Fluent Reader, FocusReader, Read You, etc.).

## How SSO works (Pattern A — trusted header)

  1. OpenHost router validates the visitor's `zone_auth` cookie and
     stamps `X-OpenHost-Is-Owner: true` on owner requests.
  2. The bundled `auth_proxy.py` reads that header and re-stamps
     the request as `X-WebAuth-User: admin` before forwarding to
     FreshRSS' apache backend.
  3. FreshRSS' install bootstrap runs `cli/do-install.php` with
     `--auth-type http_auth`, which makes the app read
     `$_SERVER['HTTP_X_WEBAUTH_USER']` on every request as the
     authenticated user.

Anonymous visitors that bypass OpenHost's auth get nothing — the
router 302's them to `/login`, never reaching the auth-proxy.

Defence in depth: the auth-proxy strips any client-supplied
`X-OpenHost-*` / `X-WebAuth-User` / `Remote-User` headers before
forwarding, so a hostile actor who somehow bypassed the router
cannot inject a fake admin identity.

## Data

  * `/data/app_data/freshrss/` — FreshRSS' SQLite DB, user config,
    extensions, OPML state.  Symlinked into the container as
    `/var/www/FreshRSS/data`.
  * `/data/app_temp_data/freshrss/` — apache scratch space.

No plaintext passwords are written to disk.  The "admin" user
created by the install bootstrap has no usable password (FreshRSS
keeps it empty when auth_type is `http_auth`), so nothing on the
file-browser-readable volume is a credential.

## Manifest

  * Port 8080 (auth-proxy)
  * Apache shimmed to 127.0.0.1:8800 via the `LISTEN` env var
  * Cron-driven feed refresh every 15 minutes (CRON_MIN override
    via container env)

## Verifying

```sh
# Owner SSO — should land on the FreshRSS dashboard without any
# login form.
curl -sk -H "Authorization: Bearer $OPENHOST_TOKEN" \
    -L "https://freshrss.${OPENHOST_ZONE_DOMAIN}/" \
    -o /tmp/r.html -w 'HTTP=%{http_code}\nFINAL=%{url_effective}\n'
grep -oE '<title>[^<]+</title>' /tmp/r.html

# Anonymous — should redirect to OpenHost /login.
curl -sk -L "https://freshrss.${OPENHOST_ZONE_DOMAIN}/" \
    -w 'HTTP=%{http_code}\nFINAL=%{url_effective}\n' -o /dev/null
```
