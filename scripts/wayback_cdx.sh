#!/usr/bin/env bash
# Sustituto de waybackurls: consulta directa al CDX de archive.org (pasivo, no toca el target).
# waybackurls devolvía 0 URLs sin error (fallo silencioso). Lee el dominio raíz por stdin, escribe URLs por stdout.
# Si archive.org no responde 200 en ninguna consulta, sale con error para que fetch_hist lo marque FUENTE CAÍDA.
read -r root
[ -z "$root" ] && exit 2
UA="${UA:-Mozilla/5.0 (atalaya)}"
LIMIT="${WAYBACK_LIMIT:-200000}"
tmp=$(mktemp); acc=$(mktemp); ok=0; last=""; trunc=""
for pat in "%2A.${root}/%2A" "${root}/%2A"; do
    code=$(curl -s -A "$UA" --max-time 150 --retry 2 --retry-delay 10 -o "$tmp" -w "%{http_code}" \
        "https://web.archive.org/cdx/search/cdx?url=${pat}&fl=original&collapse=urlkey&limit=${LIMIT}")
    if [ "$code" = "200" ]; then
        ok=1; cat "$tmp" >> "$acc"
        # F6 (16-nov): si devuelve justo el tope, el historial está CORTADO (antes pasaba sin avisar).
        # Se completa con consultas dirigidas a lo que nos interesa: URLs con parámetros y rutas /api/ o .js
        if [ "$(wc -l < "$tmp")" -ge "$LIMIT" ]; then
            trunc="$trunc $pat"
            for flt in "original:.*%5C%3F.*" "original:.*%28/api/%7C%5C.js%29.*"; do
                sleep 2
                c2=$(curl -s -A "$UA" --max-time 150 --retry 2 --retry-delay 10 -o "$tmp" -w "%{http_code}" \
                    "https://web.archive.org/cdx/search/cdx?url=${pat}&fl=original&collapse=urlkey&filter=${flt}&limit=${LIMIT}")
                [ "$c2" = "200" ] && cat "$tmp" >> "$acc"
            done
        fi
    else last="$code"; fi
    sleep 2
done
[ -n "$trunc" ] && echo "TRUNCADO: el CDX devolvió el tope (${LIMIT}) en${trunc}; completado con consultas dirigidas (parámetros, /api/, .js)" >&2
# fuera ruido de WAF (Imperva/Incapsula, Cloudflare challenge): no son rutas de la app
grep -viE "/_Incapsula_Resource|/cdn-cgi/|/__cf_chl" "$acc" | sort -u
rm -f "$tmp" "$acc"
if [ "$ok" -ne 1 ]; then echo "archive.org CDX http=${last:-sin respuesta}" >&2; exit 1; fi
exit 0
