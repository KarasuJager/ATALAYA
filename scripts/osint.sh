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
# yaml del programa (scope/reglas/known_dups) montado desde aegir-vps/programs
[ -z "${PROGRAM_YAML:-}" ] && [ -f "/programs/${PROGRAM}.yaml" ] && PROGRAM_YAML="/programs/${PROGRAM}.yaml"
# Identificación del tráfico activo (whatweb, wafw00f). Pasivo (crt.sh, wayback, gau, whois, dns) no lleva.
HANDLE="${HANDLE:-researcher}"
UA="${UA_OVERRIDE:-bugbounty-${HANDLE}}"
export UA   # lo usan los scripts auxiliares (wayback_cdx.sh)
IDENT_HEADER="${IDENT_HEADER:-X-Bug-Bounty}"
HDRS=$(mktemp); printf 'User-Agent: %s\n%s: %s\n' "$UA" "$IDENT_HEADER" "$HANDLE" > "$HDRS"
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
    curl -s --max-time 90 "https://crt.sh/?q=%25.${root}&output=json" -o "$OUT/crtsh/${root}.json" 2>/dev/null || true
    jq -r '.[].name_value' "$OUT/crtsh/${root}.json" 2>/dev/null \
        | sed 's/\*\.//g' | tr 'A-Z' 'a-z' \
        | sort -u > "$OUT/crtsh/${root}.txt" || true
    COUNT=$(wc -l < "$OUT/crtsh/${root}.txt" 2>/dev/null || echo 0)
    echo "    $COUNT subdomains from certificates"
    sleep 1
done
# Si el scope son hosts concretos (app-staging.x.com), consultar también el dominio registrable (x.com)
# en crt.sh: es PASIVO (no toca el target) y descubre hermanos (*-staging) que luego filtra el scope-guard.
PARENTS=$(for r in $ROOTS; do python3 -c "import sys;sys.path.insert(0,'/app/intel');from common import registrable;print(registrable(sys.argv[1]))" "$r"; done | sort -u)
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
        # 18-nov: con set -e, "cmd; rc=$?" mataba el script al primer fallo (archive.org caido) antes de reintentar
        if echo "$root" | timeout "$tmo" "$@" > "$out" 2> "$err"; then rc=0; else rc=$?; fi
        # waybackurls/gau devuelven 0 aunque la fuente falle: 0 líneas + algo en stderr = fallo
        if [ $rc -eq 0 ] && [ ! -s "$out" ] && [ -s "$err" ]; then rc=99; fi
        [ $rc -eq 0 ] && break
        [ $n -lt "$tries" ] && { echo "    [$src] intento $n falló (rc=$rc), reintento en $((n*30))s..."; sleep $((n*30)); }
        n=$((n+1))
    done
    local count; count=$(wc -l < "$out" 2>/dev/null || echo 0)
    if [ $rc -eq 0 ]; then
        if grep -q "TRUNCADO" "$err" 2>/dev/null; then
            echo "$root | $src | ok $count $(grep -m1 TRUNCADO "$err" | cut -c1-160)" >> "$STATUS"
            echo "    $count URLs ($src) — TRUNCADO: la fuente cortó en su tope; completado con consultas dirigidas"
        else
            echo "$root | $src | ok $count" >> "$STATUS"
            echo "    $count URLs ($src)"
        fi
        rm -f "$err"
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
    # waybackurls fallaba en silencio (0 URLs sin error) → consulta directa al CDX de archive.org
    fetch_hist wayback "$root" "$OUT/wayback/${root}.txt" 330 2 bash /app/scripts/wayback_cdx.sh
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

# ---- Gate de tráfico activo: whatweb/wafw00f tocan el target. wafw00f envía payloads XSS/SQLi/LFI
# para provocar al WAF → solo si el programa lo permite (programs/<p>.yaml: vps.passive_only / texto "no automation").
ACTIVE_OK="yes"
if [ -n "${PROGRAM_YAML:-}" ] && [ -f "$PROGRAM_YAML" ]; then
    ACTIVE_OK=$(python3 -c "import sys;sys.path.insert(0,'/app/intel');from common import load_program,passive_only;p,_=load_program(sys.argv[1]);print('no' if passive_only(p) else 'yes')" "$PROGRAM_YAML" 2>/dev/null || echo no)
fi
[ "${ATALAYA_PASSIVE:-0}" = "1" ] && ACTIVE_OK="no"
echo "[*] Tráfico activo (whatweb/wafw00f): $ACTIVE_OK"

echo "══════════════════════════════════════════"
echo " [6/8] WhatWeb (Technology Fingerprint)"
echo "══════════════════════════════════════════"
[ "$ACTIVE_OK" = "yes" ] && for root in $ROOTS; do
    for proto in https http; do
        echo "  → ${proto}://${root}"
        whatweb --color=never -a 3 -U "$UA" -H "${IDENT_HEADER}:${HANDLE}" "${proto}://${root}" \
            --log-json "$OUT/whatweb/${root}-${proto}.json" \
            2>/dev/null || true
    done
done
echo ""

echo "══════════════════════════════════════════"
echo " [7/8] wafw00f (WAF Detection)"
echo "══════════════════════════════════════════"
[ "$ACTIVE_OK" = "yes" ] && [ "${WAFW00F_ALL:-0}" = "1" ] && WAFFLAG="-a" || WAFFLAG=""
[ "$ACTIVE_OK" = "yes" ] && for root in $ROOTS; do
    echo "  → $root"
    wafw00f $WAFFLAG "https://${root}" -H "$HDRS" -o "$OUT/wafw00f/${root}.json" -f json \
        2>/dev/null || true
done
echo ""

echo "══════════════════════════════════════════"
echo " [8/8] theHarvester"
echo "══════════════════════════════════════════"
# Solo fuentes gratuitas y pasivas que existen en 4.11.1. NUNCA las de brechas/credenciales
# (dehashed, haveibeenpwned, hudsonrock, leaklookup, intelx...): regla AEGIR.
THV_SOURCES="${THV_SOURCES:-baidu,certspotter,commoncrawl,crtsh,duckduckgo,hackertarget,otx,rapiddns,robtex,subdomaincenter,thc,urlscan}"
for root in $ROOTS; do
    echo "  → $root (fuentes gratuitas y pasivas)"
    log="$OUT/theharvester/${root}.log"
    rc=0
    # ".out": theHarvester corta el nombre por el último punto (app.example.com -> app.example.json); así queda <root>.json
    ( cd "$OUT/theharvester" && timeout 900 theHarvester -d "$root" -b "$THV_SOURCES" -l 500 \
        -f "$OUT/theharvester/${root}.out" ) > "$log" 2>&1 || rc=$?
    n=$(python3 -c "import json,sys
try: print(len(json.load(open(sys.argv[1])).get('hosts') or []))
except Exception: print(-1)" "$OUT/theharvester/${root}.json" || echo -1)
    if [ "$rc" -eq 0 ] && [ "$n" -ge 0 ]; then
        echo "$root | theharvester | ok $n" >> "$STATUS"
        echo "    $n hosts (theHarvester)"
    else
        why=$(grep -iE "error|exception|invalid" "$log" 2>/dev/null | tail -2 | tr '\n' ' ' | cut -c1-180 || true)
        echo "$root | theharvester | FAILED rc=$rc ${why}" >> "$STATUS"
        echo "    theHarvester FALLÓ (rc=$rc) — ver theharvester/${root}.log"
    fi
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

# Hosts de theHarvester desde su JSON (campo "hosts", sin la IP); el XML traía también dominios de emails y terceros
python3 -c "import json,glob
for f in glob.glob('$OUT/theharvester/*.json'):
    try:
        for h in json.load(open(f)).get('hosts') or []: print(str(h).split(':')[0].strip().lower())
    except Exception: pass" > "$OUT/theharvester/_hosts.txt" 2>/dev/null || true
cat "$OUT"/crtsh/*.txt "$OUT"/theharvester/_hosts.txt 2>/dev/null \
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
echo ""
echo "══════════════════════════════════════════"
echo " [9/9] Intel — visión de bounty (pasivo)"
echo "══════════════════════════════════════════"
python3 /app/intel/run.py "$OUT" ${PROGRAM_YAML:+--program-yaml "$PROGRAM_YAML"} --scope-txt "$1" || echo "  [!] intel falló (los datos crudos siguen ahí)"
# (sin symlink "latest": el host es Windows; el orquestador elige el último dir por nombre)
echo " BRIEFING: $OUT/BRIEFING.md"
echo "============================================"
