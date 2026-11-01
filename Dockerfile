# ============================================================
# OSINT Pipeline — Pre-hunt intelligence gathering
# Part of AEGIR Security bug bounty toolkit
# ============================================================
# Stage 1: compile Go tools (waybackurls, gau)
# ============================================================
FROM golang:1.22-bookworm AS go-builder

RUN go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest

# ============================================================
# Stage 2: main image
# ============================================================
FROM python:3.12-slim-bookworm

LABEL maintainer="Manuel Miguel Fernandez-Gallego Olivares"
LABEL description="OSINT pipeline for bug bounty pre-hunt intelligence"

# ---- system deps -------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        ruby ruby-dev build-essential libffi-dev \
        dnsutils whois curl jq git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---- Go binaries from builder ------------------------------
COPY --from=go-builder /go/bin/waybackurls /usr/local/bin/waybackurls
COPY --from=go-builder /go/bin/gau /usr/local/bin/gau

# ---- whatweb (Ruby) ----------------------------------------
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    cd /opt/whatweb && \
    gem install bundler && \
    bundle install --gemfile=/opt/whatweb/Gemfile 2>/dev/null || true && \
    ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb

# ---- wafw00f (Python) --------------------------------------
RUN pip install --break-system-packages wafw00f

# ---- dnsrecon (Python) -------------------------------------
RUN pip install --break-system-packages dnsrecon

# ---- theHarvester (Python) ---------------------------------
RUN git clone --depth 1 https://github.com/laramies/theHarvester.git /opt/theHarvester && \
    cd /opt/theHarvester && \
    pip install --break-system-packages -r requirements.txt 2>/dev/null || \
    pip install --break-system-packages -e . 2>/dev/null || true

# ---- Shodan CLI (optional, needs API key) ------------------
RUN pip install --break-system-packages shodan

# ---- app scripts -------------------------------------------
COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/*.sh /app/scripts/*.py 2>/dev/null || true

WORKDIR /app

ENTRYPOINT ["/app/scripts/osint.sh"]
