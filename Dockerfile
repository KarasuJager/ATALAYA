# ============================================================
# OSINT Pipeline — Pre-hunt intelligence gathering
# Part of AEGIR Security bug bounty toolkit
# ============================================================
# Stage 1: compile Go tools (waybackurls, gau)
# ============================================================
FROM golang:1.24-bookworm AS go-builder
# bbscope v2 exige Go >= 1.27: deja que go descargue el toolchain que pida cada módulo
ENV GOTOOLCHAIN=auto

RUN go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest

# ---- Atalaya v3: análisis de JS, sourcemaps, GitHub y scope de plataformas (todo pasivo)
RUN go install github.com/BishopFox/jsluice/cmd/jsluice@latest && \
    go install github.com/denandz/sourcemapper@latest && \
    go install github.com/gwen001/github-subdomains@latest && \
    go install github.com/gwen001/github-endpoints@latest && \
    go install github.com/sw33tLie/bbscope/v2@latest

# ---- trufflehog (binario oficial)
FROM trufflesecurity/trufflehog:latest AS trufflehog

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
COPY --from=go-builder /go/bin/jsluice /go/bin/sourcemapper /go/bin/github-subdomains /go/bin/github-endpoints /go/bin/bbscope /usr/local/bin/
COPY --from=trufflehog /usr/bin/trufflehog /usr/local/bin/trufflehog

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
# Fijado a 4.11.1: la rama main exige Python 3.14 y esta imagen es 3.12. Antes el fallo se tapaba con
# "2>/dev/null || true" y theHarvester NUNCA llegó a instalarse (F3, 16-nov). Ahora, si falla, falla la construcción.
RUN git clone --depth 1 --branch 4.11.1 https://github.com/laramies/theHarvester.git /opt/theHarvester && \
    pip install --break-system-packages /opt/theHarvester && \
    theHarvester -h > /dev/null

# ---- Shodan CLI (optional, needs API key) ------------------
RUN pip install --break-system-packages shodan

# ---- intel (visión de bounty) ------------------------------
RUN pip install --break-system-packages pyyaml requests porch-pirate

# ---- app scripts -------------------------------------------
COPY scripts/ /app/scripts/
COPY intel/ /app/intel/
RUN chmod +x /app/scripts/*.sh /app/scripts/*.py 2>/dev/null || true

WORKDIR /app

ENTRYPOINT ["/app/scripts/osint.sh"]
