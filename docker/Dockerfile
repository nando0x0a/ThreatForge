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

RUN curl -fsSL "https://api.github.com/repos/projectdiscovery/pdtm/releases/latest" \
    | jq -r '.assets[] | select(.name | test("linux_amd64.zip")) | .browser_download_url' \
    | xargs curl -fsSL -o /tmp/pdtm.zip \
    && unzip /tmp/pdtm.zip pdtm -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/pdtm \
    && rm /tmp/pdtm.zip
ENV PATH="/root/.pdtm/go/bin:$PATH"
RUN pdtm -install vulnx

# vulnx auth is handled at runtime via PDCP_API_KEY env var

WORKDIR /opt/vuln-skill

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY config/products.txt ./config/products.txt
COPY config/vuln-skill.yaml ./config/vuln-skill.yaml
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

RUN mkdir -p outputs/{rules,advisories,iocs,hunting,patches} logs

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python3 -c "import anthropic, openai; print('ok')" || exit 1

# web-bugs-and-tweaks.md #37: the scheduler (supercronic + a
# scheduler.enabled config flag) was removed -- it was always disabled by
# default and nothing (no cron, no systemd timer) ever actually enabled
# it in either deployment. entrypoint.sh now just idles unconditionally;
# a run always happens via an explicit docker exec / the web UI instead.
CMD ["/usr/local/bin/entrypoint.sh"]
