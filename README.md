# FreshRSS for Cloud in a Bottle

[FreshRSS](https://www.freshrss.org/) packaged for Cloud in a Bottle with
single sign-on for the instance owner.

## What it is

A self-hosted RSS / Atom feed aggregator.  Web UI for reading
feeds, mobile-friendly, supports OPML import/export, Fever API,
Google Reader API, and the FreshRSS native API for third-party
clients (Fluent Reader, FocusReader, Read You, etc.).

## Features

- Official FreshRSS `1.30.0-alpine` image pinned for reproducible builds.
- SQLite configuration, users, feeds, and extension data in permanent storage.
- Feed refreshes at minutes 7 and 37 of every hour.
- Empty feed list for every newly created user.
- Native, Fever, and Google Reader compatible APIs.

## How SSO works

1. The Cloud in a Bottle router authenticates the visitor and stamps
   `X-OpenHost-Is-Owner: true` on owner requests.
2. `auth_proxy.py` translates that trusted signal to
   `X-WebAuth-User: admin` before forwarding to loopback-only Apache.
3. FreshRSS uses `http_auth`, so the owner arrives as the `admin` user without
   another password prompt.

Anonymous visitors are redirected to the instance login before reaching the
container. Only the static `/healthz` response is public.

Defense in depth: the auth proxy strips any client-supplied
`X-OpenHost-*` / `X-WebAuth-User` / `Remote-User` headers before
forwarding, so a hostile actor who somehow bypassed the router
cannot inject a fake admin identity.

## Data

- `$BOTTLE_APP_DATA_DIR/data` contains FreshRSS's SQLite database, user
  configuration, extension data, and OPML state.

No plaintext passwords are written to disk.  The "admin" user
created by the install bootstrap has no usable password (FreshRSS
keeps it empty when auth_type is `http_auth`), so nothing on the
file-browser-readable volume is a credential.

## Deploy

```sh
bottle app deploy https://github.com/cloud-in-a-bottle/bottled-freshrss --wait
```

The app is available at `https://freshrss.<your-domain>/`.

## Default Feeds

There are none. The package replaces FreshRSS's onboarding OPML with a valid
empty document and passes `--no-default-feeds` when creating the owner. Add
subscriptions in the UI or import an OPML file after deployment.

## Development

```sh
python -m pytest -q
```
