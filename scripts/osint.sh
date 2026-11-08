#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#    _  _____  _    _        _ __   __  _
#   / \|_   _|/ \  | |      / \  \ / / / \
#  / _ \ | | / _ \ | |     / _ \  V / / _ \
# / ___ \| |/ ___ \| |___ / ___ \ | |/ ___ \
#/_/   \_\_/_/   \_\_____/_/   \_\|_/_/   \_\
#
#  AEGIR Security — Atalaya
#  Pre-hunt intelligence for bug bounty
# ============================================================

SCOPE="${1:?Usage: osint.sh <scope-file> [shodan-api-key]}"
SHODAN_KEY="${2:-}"

if [ ! -f "$SCOPE" ]; then
    echo "[!] Scope file not found: $SCOPE"
    exit 1
fi

# Sanitize scope file (PowerShell writes UTF-16/BOM — strip it)
CLEAN_SCOPE=$(mktemp)
LC_ALL=C sed "1s/^\xef\xbb\xbf//" "$SCOPE" | sed 's/\r$//' | tr -d '\0' > "$CLEAN_SCOPE"
SCOPE="$CLEAN_SCOPE"

PROGRAM=$(basename "$1" .txt)
# Identificación del tráfico activo (whatweb, wafw00f). Pasivo (crt.sh, wayback, gau, whois, dns) no lleva.
HANDLE="${HANDLE:-researcher}"
UA="${UA_OVERRIDE:-bugbounty-${HANDLE}}"
HDRS=$(mktemp); printf 'User-Agent: %s\nX-Bug-Bounty: %s\n' "$UA" "$HANDLE" > "$HDRS"
echo " UA: $UA"
TS=$(date +%Y%m%d-%H%M%S)
OUT="/data/${PROGRAM}/${TS}"
mkdir -p "$OUT"/{wayback,gau,whatweb,wafw00f,dns,whois,crtsh,theharvester,shodan,merged}

ln -sfn "$TS" "/data/${PROGRAM}/latest"

echo "============================================"
echo " Atalaya — $PROGRAM"
echo " $(date)"
echo " Output: $OUT"
echo "============================================"
echo ""

ROOTS=$(grep -v '^\s*#' "$SCOPE" | grep -v '^\s*$' | sort -u)
TOTAL=$(echo "$ROOTS" | wc -l)
echo "[*] $TOTAL root domains to process"
echo ""

echo "══════════════════════════════════════════"
echo " [1/8] Certificate Transparency (crt.sh)"
echo "══════════════════════════════════════════"
for root in $ROOTS; do
    echo "  → $root"
    curl -s "https://crt.sh/?q=%25.${root}&output=json" 2>/dev/null \
        | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' \
        | sort -u > "$OUT/crtsh/${root}.txt" || true
    COUNT=$(wc -l < "$OUT/crtsh/${root}.txt" 2>/dev/null || echo 0)
    echo "    $COUNT subdomains from certificates"
    sleep 1
done
# Si el scope son hosts concretos (app-staging.x.com), consultar también el dominio registrable (x.com)
# en crt.sh: es PASIVO (no toca el target) y descubre hermanos (*-staging) que luego filtra el scope-guard.
PARENTS=$(for r in $ROOTS; do echo "$r" | awk -F. 'NF>2{print $(NF-1)"."$NF}'; done | sort -u)
for parent in $PARENTS; do
    echo "$ROOTS" | grep -qx "$parent" && continue
    echo "  → $parent (dominio registrable, pasivo)"
    curl -s "https://crt.sh/?q=%25.${parent}&output=json" 2>/dev/null \
        | jq -r '.[].name_value' 2>/dev/null \
        | sed 's/\*\.//g' \
        | sort -u > "$OUT/crtsh/${parent}.parent.txt" || true
    COUNT=$(wc -l < "$OUT/crtsh/${parent}.parent.txt" 2>/dev/null || echo 0)
    echo "    $COUNT subdomains from certificates (candidatos: el scope decide)"
    sleep 1
done
echo ""

echo "══════════════════════════════════════════"
echo " [2/8] WHOIS"
echo "══════════════════════════════════════════"
for root in $ROOTS; do
    echo "  → $root"
    whois "$root" > "$OUT/whois/${root}.txt" 2>/dev/null || true
    grep -iE 'org-name|orgname|organization|registrant|creation|expir|name.server|asn|netrange|cidr' \
        "$OUT/whois/${root}.txt" 2>/dev/null | head -20 || true
done
echo ""

echo "══════════════════════════════════════════"
echo " [3/8] DNS Recon"
echo "══════════════════════════════════════════"
for root in $ROOTS; do
    echo "  → $root"
    {
        echo "=== A ===" && dig +short A "$root" 2>/dev/null || true
        echo "=== AAAA ===" && dig +short AAAA "$root" 2>/dev/null || true
        echo "=== MX ===" && dig +short MX "$root" 2>/dev/null || true
        echo "=== TXT ===" && dig +short TXT "$root" 2>/dev/null || true
        echo "=== CNAME ===" && dig +short CNAME "$root" 2>/dev/null || true
        echo "=== NS ===" && dig +short NS "$root" 2>/dev/null || true
        echo "=== SOA ===" && dig +short SOA "$root" 2>/dev/null || true
    } > "$OUT/dns/${root}-basic.txt"
    dnsrecon -d "$root" -t std --json "$OUT/dns/${root}-dnsrecon.json" 2>/dev/null || \
    python3 -m dnsrecon -d "$root" -t std -j "$OUT/dns/${root}-dnsrecon.json" 2>/dev/null || true
    echo "    DNS records saved"
done
echo ""

# Estado de las fuentes históricas: "0 URLs" no es lo mismo que "la fuente no respondió".
# Se escribe merged/_sources-status.txt (host | fuente | ok N / FAILED motivo) para que el bridge/Capitán
# no lean un fallo de archive.org como "este host no tiene historial". (Caída del CDX de Wayback, 8-nov-2026.)
STATUS="$OUT/merged/_sources-status.txt"
: > "$STATUS"

# fetch_hist <fuente> <root> <fichero> <timeout_s> <intentos> -- <comando...>
# Reintenta con espera creciente si el comando falla/expira. Solo cuenta como OK si salió con 0.
fetch_hist() {
    local src="$1" root="$2" out="$3" tmo="$4" tries="$5"; shift 5
    local err="${out%.txt}.err" n=1 rc=1
    while [ $n -le "$tries" ]; do
        echo "$root" | timeout "$tmo" "$@" > "$out" 2> "$err"; rc=$?
        # waybackurls/gau devuelven 0 aunque la fuente falle: 0 líneas + algo en stderr = fallo
        if [ $rc -eq 0 ] && [ ! -s "$out" ] && [ -s "$err" ]; then rc=99; fi
        [ $rc -eq 0 ] && break
        [ $n -lt "$tries" ] && { echo "    [$src] intento $n falló (rc=$rc), reintento en $((n*30))s..."; sleep $((n*30)); }
        n=$((n+1))
    done
    local count; count=$(wc -l < "$out" 2>/dev/null || echo 0)
    if [ $rc -eq 0 ]; then
        echo "$root | $src | ok $count" >> "$STATUS"; rm -f "$err"
        echo "    $count URLs ($src)"
    else
        local why; why=$(tail -c 200 "$err" 2>/dev/null | tr '\n' ' '); [ $rc -eq 124 ] && why="timeout ${tmo}s $why"
        echo "$root | $src | FAILED rc=$rc ${why}" >> "$STATUS"
        echo "    $count URLs ($src) — FUENTE CAÍDA/sin respuesta (rc=$rc), no significa que no haya historial"
    fi
}

echo "══════════════════════════════════════════"
echo " [4/8] Wayback URLs"
echo "══════════════════════════════════════════"
for root in $ROOTS; do
    echo "  → $root"
    fetch_hist wayback "$root" "$OUT/wayback/${root}.txt" 180 3 waybackurls
done
echo ""

echo "══════════════════════════════════════════"
echo " [5/8] GAU (GetAllUrls)"
echo "══════════════════════════════════════════"
for root in $ROOTS; do
    echo "  → $root"
    fetch_hist gau "$root" "$OUT/gau/${root}.txt" 900 2 gau --threads 3
done
echo ""
FAILED=$(grep -c FAILED "$STATUS" 2>/dev/null || echo 0)
[ "$FAILED" -gt 0 ] && echo "  [!] $FAILED consultas históricas fallaron — ver merged/_sources-status.txt"
echo ""

echo "══════════════════════════════════════════"
echo " [6/8] WhatWeb (Technology Fingerprint)"
echo "══════════════════════════════════════════"
for root in $ROOTS; do
    for proto in https http; do
        echo "  → ${proto}://${root}"
        whatweb --color=never -a 3 -U "$UA" -H "X-Bug-Bounty:${HANDLE}" "${proto}://${root}" \
            --log-json "$OUT/whatweb/${root}-${proto}.json" \
            2>/dev/null || true
    done
done
echo ""

echo "══════════════════════════════════════════"
echo " [7/8] wafw00f (WAF Detection)"
echo "══════════════════════════════════════════"
for root in $ROOTS; do
    echo "  → $root"
    wafw00f -a "https://${root}" -H "$HDRS" -o "$OUT/wafw00f/${root}.json" -f json \
        2>/dev/null || true
done
echo ""

echo "══════════════════════════════════════════"
echo " [8/8] theHarvester"
echo "══════════════════════════════════════════"
for root in $ROOTS; do
    echo "  → $root (free sources only)"
    cd /opt/theHarvester && python3 -m theHarvester \
        -d "$root" \
        -b anubis,baidu,bing,certspotter,crtsh,dnsdumpster,duckduckgo,hackertarget,rapiddns,subdomaincenter,urlscan \
        -f "$OUT/theharvester/${root}" \
        2>/dev/null || true
done
echo ""

if [ -n "$SHODAN_KEY" ]; then
    echo "══════════════════════════════════════════"
    echo " [BONUS] Shodan"
    echo "══════════════════════════════════════════"
    shodan init "$SHODAN_KEY" 2>/dev/null || true
    for root in $ROOTS; do
        echo "  → $root"
        shodan search "hostname:${root}" --fields ip_str,port,org,product,version \
            > "$OUT/shodan/${root}.txt" 2>/dev/null || true
        shodan host "$(dig +short A "$root" 2>/dev/null | head -1)" \
            > "$OUT/shodan/${root}-host.txt" 2>/dev/null || true
    done
    echo ""
fi

echo "══════════════════════════════════════════"
echo " Merging results"
echo "══════════════════════════════════════════"

cat "$OUT"/wayback/*.txt "$OUT"/gau/*.txt 2>/dev/null | sort -u > "$OUT/merged/all-historical-urls.txt"
HIST_COUNT=$(wc -l < "$OUT/merged/all-historical-urls.txt")
echo "  → $HIST_COUNT unique historical URLs"

grep -iE '\.(json|xml|yaml|yml|env|config|conf|bak|old|log|sql|zip|tar|gz|php|asp|jsp|do|action)\b' \
    "$OUT/merged/all-historical-urls.txt" > "$OUT/merged/interesting-urls.txt" 2>/dev/null || true
grep -iE '(api|admin|internal|debug|test|staging|dev|backup|upload|download|export|import|config|setting|account|user|profile|password|token|auth|login|register|reset|verify|confirm)' \
    "$OUT/merged/all-historical-urls.txt" > "$OUT/merged/sensitive-urls.txt" 2>/dev/null || true
INT_COUNT=$(wc -l < "$OUT/merged/interesting-urls.txt" 2>/dev/null || echo 0)
SENS_COUNT=$(wc -l < "$OUT/merged/sensitive-urls.txt" 2>/dev/null || echo 0)
echo "  → $INT_COUNT interesting file extensions"
echo "  → $SENS_COUNT sensitive path patterns"

cat "$OUT"/crtsh/*.txt "$OUT"/theharvester/*.xml 2>/dev/null \
    | grep -oP '[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' \
    | sort -u > "$OUT/merged/all-subdomains.txt" 2>/dev/null || true
SUB_COUNT=$(wc -l < "$OUT/merged/all-subdomains.txt" 2>/dev/null || echo 0)
echo "  → $SUB_COUNT unique subdomains (crt.sh + theHarvester)"

echo ""
echo "============================================"
echo " Atalaya complete — $OUT"
echo "============================================"
echo ""
echo " Subdomains:      $SUB_COUNT"
echo " Historical URLs: $HIST_COUNT"
echo "   Interesting:   $INT_COUNT"
echo "   Sensitive:     $SENS_COUNT"
echo ""
echo " Next: OSINTAgent processes this → briefing"
echo "============================================"
