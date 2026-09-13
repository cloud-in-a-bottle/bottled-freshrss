# Layer Cloud in a Bottle authentication and bootstrap wiring onto a reviewed
# FreshRSS release. Dependabot can propose deliberate version updates.
FROM freshrss/freshrss:1.30.0-alpine

USER root
RUN apk add --no-cache bash python3 ca-certificates

COPY auth_proxy.py /opt/auth_proxy.py
COPY start.sh /opt/start.sh
COPY opml.default.xml /var/www/FreshRSS/opml.default.xml
RUN chmod 0755 /opt/auth_proxy.py /opt/start.sh

# Healthcheck endpoint the auth-proxy serves locally so Cloud in a Bottle's
# probe is decoupled from FreshRSS' cold-start time.
EXPOSE 8080

ENTRYPOINT ["/opt/start.sh"]
