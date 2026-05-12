# Multi-stage: pick up upstream FreshRSS image as the base and layer
# in the OpenHost auth-proxy + bootstrap wiring on top.
FROM freshrss/freshrss:latest

# python3 + bash for the auth-proxy and start.sh.  busybox-static for
# a stable `sed`/`sleep` in start.sh that survives any future
# upstream-image alpine/debian shuffle.
USER root
RUN set -eux; \
    if command -v apt-get >/dev/null 2>&1; then \
        apt-get update; \
        apt-get install -y --no-install-recommends \
            python3 \
            ca-certificates; \
        rm -rf /var/lib/apt/lists/*; \
    elif command -v apk >/dev/null 2>&1; then \
        apk add --no-cache python3 ca-certificates; \
    else \
        echo "unknown base image package manager"; exit 1; \
    fi

COPY auth_proxy.py /opt/auth_proxy.py
COPY start.sh /opt/start.sh
RUN chmod 0755 /opt/auth_proxy.py /opt/start.sh

# Healthcheck endpoint the auth-proxy serves locally so OpenHost's
# probe is decoupled from FreshRSS' cold-start time.
EXPOSE 8080

ENTRYPOINT ["/opt/start.sh"]
