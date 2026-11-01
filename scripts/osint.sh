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

PROGRAM=$(basename "$SCOPE" .txt)
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

echo "══════════════════════════════════════════"
echo " [4/8] Wayback URLs"
echo "══════════════════════════════════════════"
for root in $ROOTS; do
    echo "  → $root"
    echo "$root" | waybackurls > "$OUT/wayback/${root}.txt" 2>/dev/null || true
    COUNT=$(wc -l < "$OUT/wayback/${root}.txt" 2>/dev/null || echo 0)
    echo "    $COUNT historical URLs"
done
echo ""

echo "══════════════════════════════════════════"
echo " [5/8] GAU (GetAllUrls)"
echo "══════════════════════════════════════════"
for root in $ROOTS; do
    echo "  → $root"
    echo "$root" | gau --threads 3 > "$OUT/gau/${root}.txt" 2>/dev/null || true
    COUNT=$(wc -l < "$OUT/gau/${root}.txt" 2>/dev/null || echo 0)
    echo "    $COUNT URLs from all sources"
done
echo ""

echo "══════════════════════════════════════════"
echo " [6/8] WhatWeb (Technology Fingerprint)"
echo "══════════════════════════════════════════"
for root in $ROOTS; do
    for proto in https http; do
        echo "  → ${proto}://${root}"
        whatweb --color=never -a 3 "${proto}://${root}" \
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
    wafw00f -a "https://${root}" -o "$OUT/wafw00f/${root}.json" -f json \
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
