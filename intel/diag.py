#!/usr/bin/env python3
"""Prueba rápida de fuentes (1 dominio): Postman (API oficial) y Wayback CDX. Uso:
docker compose run --rm --entrypoint python3 osint /app/intel/diag.py <dominio>"""
import os, subprocess, sys, json
sys.path.insert(0, os.path.dirname(__file__))
import m_sources
from common import Scope
dom = sys.argv[1] if len(sys.argv) > 1 else "example.com"
sc = Scope([dom, "*." + dom], [])
print(f"== Postman (api.postman.com/search) para {dom}")
for el in ("requests", "collections", "workspaces"):
    items, code = m_sources._pm_search(dom, el, os.environ.get("POSTMAN_API_KEY", ""), limit=10, pages=1)
    print(f"   {el:12} http={code} resultados={len(items)}" + (f"  ej: {items[0].get('name')}" if items else ""))
print(f"== Wayback CDX para {dom}")
r = subprocess.run(["bash", "/app/scripts/wayback_cdx.sh"], input=dom + "\n", capture_output=True, text=True, timeout=400)
lines = [l for l in r.stdout.splitlines() if l.strip()]
print(f"   rc={r.returncode} urls={len(lines)} {r.stderr.strip()[:200]}")
for l in lines[:3]:
    print("   ej:", l[:120])
