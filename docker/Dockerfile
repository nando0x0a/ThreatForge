FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    jq \
    git \
    unzip \
    ca-certificates \
    tzdata \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV SUPERCRONIC_URL=https://github.com/aptible/supercronic/releases/download/v0.2.29/supercronic-linux-amd64
ENV SUPERCRONIC=/usr/local/bin/supercronic
RUN curl -fsSLo "$SUPERCRONIC" "$SUPERCRONIC_URL" && chmod +x "$SUPERCRONIC"

RUN curl -fsSL "https://api.github.com/repos/projectdiscovery/pdtm/releases/latest" \
    | jq -r '.assets[] | select(.name | test("linux_amd64.zip")) | .browser_download_url' \
    | xargs curl -fsSL -o /tmp/pdtm.zip \
    && unzip /tmp/pdtm.zip pdtm -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/pdtm \
    && rm /tmp/pdtm.zip
ENV PATH="/root/.pdtm/go/bin:$PATH"
RUN pdtm -install vulnx

# vulnx auth is handled at runtime via PDCP_API_KEY env var

WORKDIR /opt/threatforge

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY config/products.txt ./config/products.txt
COPY config/threatforge.yaml ./config/threatforge.yaml

RUN echo "30 1 * * * python3 /opt/threatforge/src/orchestrate.py --scheduled" \
    > /etc/threatforge.cron

RUN mkdir -p outputs/{rules,advisories,iocs,hunting,patches} logs

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python3 -c "import anthropic, openai; print('ok')" || exit 1

CMD ["/usr/local/bin/supercronic", "/etc/threatforge.cron"]
