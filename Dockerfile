# Firewall Testkit — security test kit for Check Point Cloud Firewall deployments (east-west and egress inspection)
# One image, two roles:  server (test content + portal + reports)  |  client (agent that runs the checks)
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 TZ=UTC
RUN echo "iperf3 iperf3/start_daemon boolean false" | debconf-set-selections && apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl openssl iproute2 iputils-ping iputils-tracepath netcat-openbsd dnsutils nmap iperf3 socat \
      nginx python3 python3-flask python3-waitress python3-matplotlib fonts-dejavu-core nodejs npm tzdata \
    && rm -rf /var/lib/apt/lists/* && rm -f /etc/nginx/sites-enabled/default \
    && cp /etc/ssl/certs/ca-certificates.crt /opt/public-ca-bundle.crt
WORKDIR /opt/testkit
COPY server/report/package.json server/report/
RUN cd server/report && npm install --omit=dev --no-audit --no-fund && npm cache clean --force
COPY server/make_content.py server/
RUN python3 server/make_content.py && mv /opt/public-ca-bundle.crt /opt/testkit/public-ca-bundle.crt && mkdir -p /opt/testkit/empty-capath \
    && (curl -fsSL --max-time 60 -o /srv/www/demo/putty.exe https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe || true)
COPY catalog/tests.json catalog/
COPY config/config.example.json config/config.json
COPY client/ client/
COPY server/ server/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh client/runner.py && ln -s /opt/testkit/client/runner.py /usr/local/bin/fw-tests
ENTRYPOINT ["/entrypoint.sh"]
CMD ["client"]
