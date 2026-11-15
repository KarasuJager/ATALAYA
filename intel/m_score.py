"""Bounty score 0-100 por host: dónde mirar primero para un válido que no sea dup."""
import re, json
from pathlib import Path
from common import wjson, wlines

NONPROD = re.compile(r"(?i)(^|[.-])(dev|develop|development|test|tst|qa|uat|stag(e|ing)?|stg|sandbox|sbx|preprod|pre|np|nonprod|demo|beta|int|integration|perf|load)([0-9]*)([.-]|$)")
HOT = re.compile(r"(?i)(^|[.-])(api|apis|graphql|gql|gateway|gw|auth|sso|idp|oauth|login|account|admin|portal|console|dashboard|merchant|partner|vendor|backoffice|internal|manage|mgmt|ops|billing|pay|payments?|checkout|wallet|loan|apply|onboard|kyc)([0-9]*)([.-]|$)")
COLD = re.compile(r"(?i)(^|[.-])(www|static|assets?|img|images?|media|cdn|fonts?|blog|news|press|docs?|help|support|status|careers?|jobs|events?|go|click|email|em|links?|mail|smtp|autodiscover|investors?|ir)([0-9]*)\.")
HIGH_TECH = re.compile(r"(?i)(next\.?js|nuxt|graphql|apollo|spring|struts|rails|laravel|django|express|php|wordpress|drupal|joomla|jenkins|gitlab|grafana|kibana|elasticsearch|jira|confluence|sap|weblogic|tomcat|jboss|coldfusion|sharepoint|exchange|citrix|fortinet|pulse|f5|big-?ip|swagger|keycloak|okta)")

DEFAULT_W = {"nonprod": 20, "hot": 20, "new_vs_prev": 25, "fresh_cert": 20, "hidden_source": 15, "spec_or_map": 15,
             "api_hist": 10, "idor_hist": 10, "high_tech": 10, "vulns": 10, "odd_ports": 5, "takeover": 15,
             "secrets_js": 15, "cold": -25, "known_dup": -15, "no_dns": -10}


def score_all(hosts: dict, ctx: dict, weights=None):
    W = dict(DEFAULT_W, **(weights or {}))
    rows = []
    known_txt = (ctx.get("known_dups_text") or "").lower()
    for h, info in hosts.items():
        s, sig = 0, []
        def add(k, why):
            nonlocal s
            s += W[k]; sig.append(f"{'+' if W[k] >= 0 else ''}{W[k]} {why}")
        if NONPROD.search(h): add("nonprod", "non-prod")
        if HOT.search(h): add("hot", "api/auth/admin/pagos en el nombre")
        if COLD.search(h + ".") and not HOT.search(h): add("cold", "estático/marketing")
        if info.get("new"): add("new_vs_prev", "nuevo vs corrida anterior")
        if info.get("fresh_cert"): add("fresh_cert", f"cert nuevo {info.get('first_cert')}")
        if info.get("hidden"): add("hidden_source", "solo en fuentes de terceros (" + ",".join(info["hidden"]) + ")")
        hi = info.get("hist") or {}
        if hi.get("specs") or hi.get("sourcemaps"): add("spec_or_map", f"spec/sourcemap ({hi.get('specs',0)}/{hi.get('sourcemaps',0)})")
        if hi.get("api_routes"): add("api_hist", f"{hi['api_routes']} rutas API en historial")
        if hi.get("idor_candidates"): add("idor_hist", f"{hi['idor_candidates']} candidatos IDOR")
        tech = " ".join(info.get("tech", []))
        m = HIGH_TECH.search(tech)
        if m: add("high_tech", f"tech {m.group(1)}")
        if info.get("vulns"): add("vulns", f"{len(info['vulns'])} CVE (internetdb)")
        if [p for p in info.get("ports", []) if p not in (80, 443)]: add("odd_ports", "puertos " + ",".join(map(str, [p for p in info["ports"] if p not in (80, 443)][:6])))
        if info.get("takeover"): add("takeover", "takeover candidato " + info["takeover"])
        if info.get("js_secrets"): add("secrets_js", f"{info['js_secrets']} posibles secretos en JS archivado")
        root = ".".join(h.split(".")[-3:])
        if h in known_txt or (root in known_txt and not NONPROD.search(h) and not info.get("new")):
            add("known_dup", "zona con known issues/dups")
        if info.get("dns") == "dead" and not info.get("hidden"): add("no_dns", "no resuelve")
        rows.append({"host": h, "score": max(0, min(100, s + 30)), "raw": s, "signals": sig, "scope": info.get("scope", "in")})
    rows.sort(key=lambda r: (-r["score"], r["host"]))
    return rows


def write(rows, out_dir: Path):
    wjson(out_dir / "scores.json", rows)
    lines = ["host,score,scope,signals"] + [f'{r["host"]},{r["score"]},{r["scope"]},"{" | ".join(r["signals"])}"' for r in rows]
    wlines(out_dir / "scores.csv", lines)
