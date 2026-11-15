"""Fuentes pasivas de terceros. Ninguna toca el target: crt.sh, DNS público, internetdb, urlscan, GitHub, Postman, archive.org.
Cada fuente deja estado en sources-status (ok N / FAILED motivo) para no confundir 'caído' con 'vacío'."""
import json, os, re, subprocess, time, urllib.parse, datetime as dt
from pathlib import Path
from common import log, http, jget, wjson, wlines, rjson, rlines, host_of, registrable, HOST_RE

STATUS = []


def st(src, ok, info):
    STATUS.append({"source": src, "ok": ok, "info": str(info)[:300]})
    log(f"  [{src}] {'ok' if ok else 'FAILED'} {info}")


# ---------------------------------------------------------------- crt.sh con fechas
def ct(roots, scope, crt_dir: Path, fresh_days=45):
    """Hosts por certificado con primera/última emisión. 'fresh' = primer cert visto hace < fresh_days (superficie nueva)."""
    first, last = {}, {}
    for root in roots:
        raw = crt_dir / f"{root}.json"
        data = rjson(raw)
        if data is None:
            s, data = jget(f"https://crt.sh/?q=%25.{urllib.parse.quote(root)}&output=json", timeout=120, tries=3)
            if data is None:
                st("crt.sh", False, f"{root} http={s}"); continue
            wjson(raw, data)
        n = 0
        for c in data:
            nb = (c.get("not_before") or c.get("entry_timestamp") or "")[:10]
            for name in (c.get("name_value") or "").split("\n"):
                h = name.strip().lower().lstrip("*.")
                if not h or not scope.ok(h):
                    continue
                n += 1
                if nb:
                    first[h] = min(first.get(h, nb), nb); last[h] = max(last.get(h, nb), nb)
                else:
                    first.setdefault(h, ""); last.setdefault(h, "")
        st("crt.sh", True, f"{root}: {n} nombres en scope")
    cutoff = (dt.date.today() - dt.timedelta(days=fresh_days)).isoformat()
    hosts = {h: {"first_cert": first[h], "last_cert": last.get(h, "")} for h in first}
    fresh = sorted([h for h, v in hosts.items() if v["first_cert"] and v["first_cert"] >= cutoff])
    return hosts, fresh


# ---------------------------------------------------------------- DNS + takeover pasivo
TAKEOVER = {  # sufijo de CNAME → servicio (solo candidatos: se confirma a mano)
    "s3.amazonaws.com": "AWS S3", "s3-website": "AWS S3 website", "cloudfront.net": "CloudFront",
    "azurewebsites.net": "Azure App Service", "cloudapp.net": "Azure CloudApp", "cloudapp.azure.com": "Azure",
    "trafficmanager.net": "Azure TM", "blob.core.windows.net": "Azure Blob", "azureedge.net": "Azure CDN",
    "herokuapp.com": "Heroku", "herokudns.com": "Heroku", "github.io": "GitHub Pages", "ghost.io": "Ghost",
    "zendesk.com": "Zendesk", "myshopify.com": "Shopify", "fastly.net": "Fastly", "unbouncepages.com": "Unbounce",
    "wpengine.com": "WP Engine", "pantheonsite.io": "Pantheon", "readme.io": "Readme", "surge.sh": "Surge",
    "netlify.app": "Netlify", "netlify.com": "Netlify", "vercel.app": "Vercel", "vercel-dns.com": "Vercel",
    "helpscoutdocs.com": "HelpScout", "freshdesk.com": "Freshdesk", "statuspage.io": "Statuspage",
    "webflow.io": "Webflow", "bitbucket.io": "Bitbucket", "agilecrm.com": "AgileCRM", "smartling.com": "Smartling",
    "elasticbeanstalk.com": "Elastic Beanstalk", "firebaseapp.com": "Firebase", "web.app": "Firebase",
}


# Servicios donde un CNAME colgando NO es tomable hoy: el proveedor exige demostrar control del dominio
# (CloudFront pide certificado ACM del dominio; Azure App Service pide TXT asuid; Fastly/Zendesk verifican).
# Se listan como "DNS colgando (informativo)", sin subir la nota.
NOT_TAKEABLE = {"CloudFront", "Azure App Service", "Fastly", "Zendesk", "Shopify", "Firebase"}


def _dig(name, rtype):
    try:
        r = subprocess.run(["dig", "+time=3", "+tries=1", "+noall", "+answer", "+comments", rtype, name],
                           capture_output=True, text=True, timeout=12)
        status = re.search(r"status: (\w+)", r.stdout)
        ans = [l.split()[-1].rstrip(".") for l in r.stdout.splitlines() if l and not l.startswith(";") and len(l.split()) >= 5
               and l.split()[3] == rtype]
        return (status.group(1) if status else "ERR"), ans
    except Exception:
        return "ERR", []


def dns(hosts, max_hosts=1500):
    """A/CNAME de cada host en scope (resolución DNS normal, como cualquier navegador). Marca takeovers candidatos."""
    res, takeovers, ips = {}, [], {}
    hosts = sorted(hosts)[:max_hosts]
    t0 = time.time()
    for i, h in enumerate(hosts):
        s, cn = _dig(h, "CNAME")
        _, a = _dig(h, "A")
        res[h] = {"status": s, "cname": cn, "a": a}
        for ip in a:
            ips.setdefault(ip, []).append(h)
        for c in cn:
            for suf, svc in TAKEOVER.items():
                if suf in c:
                    cs, ca = _dig(c, "A")
                    if cs == "NXDOMAIN" or (not a and not ca):
                        takeovers.append({"host": h, "cname": c, "service": svc, "cname_status": cs})
        if i and i % 200 == 0:
            log(f"  [dns] {i}/{len(hosts)} ({int(time.time()-t0)}s)")
    alive = [h for h, v in res.items() if v["a"] or v["cname"]]
    if not alive and len(hosts) >= 20:
        st("dns", False, f"0/{len(hosts)} resuelven → resolvedor caído, no se penaliza 'sin DNS'")
        return {}, {}, []
    st("dns", True, f"{len(hosts)} consultados · {len(alive)} resuelven · {len(ips)} IPs · {len(takeovers)} takeover candidatos")
    return res, ips, takeovers


# ---------------------------------------------------------------- internetdb (Shodan, sin clave)
def internetdb(ips, max_ips=400):
    out = {}
    fails = 0
    for ip in list(ips)[:max_ips]:
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) or ip.startswith(("10.", "192.168.", "127.")):
            continue
        s, d = jget(f"https://internetdb.shodan.io/{ip}", timeout=15, tries=2)
        if d is not None:
            out[ip] = {k: d.get(k) for k in ("ports", "cpes", "vulns", "tags", "hostnames")}
        elif s != 404:
            fails += 1
        time.sleep(0.4)
    st("internetdb", fails < 5, f"{len(out)} IPs con datos · {fails} fallos")
    return out


# ---------------------------------------------------------------- urlscan (búsqueda pública)
def urlscan(roots, scope):
    key = os.environ.get("URLSCAN_API_KEY", "")
    hdr = {"API-Key": key} if key else {}
    urls, hosts = set(), {}
    for root in roots:
        s, d = jget(f"https://urlscan.io/api/v1/search/?q=domain:{urllib.parse.quote(root)}&size=1000", headers=hdr, timeout=40)
        if d is None:
            st("urlscan", False, f"{root} http={s}"); continue
        n = 0
        for r in d.get("results", []):
            pg = r.get("page") or {}
            u = pg.get("url") or (r.get("task") or {}).get("url") or ""
            h = host_of(u)
            if h and scope.ok(h):
                urls.add(u); n += 1
                e = hosts.setdefault(h, {"server": set(), "ip": set(), "seen": ""})
                if pg.get("server"): e["server"].add(pg["server"])
                if pg.get("ip"): e["ip"].add(pg["ip"])
                e["seen"] = max(e["seen"], (r.get("task") or {}).get("time", "")[:10])
        st("urlscan", True, f"{root}: {n} resultados en scope")
        time.sleep(2)
    hosts = {h: {"server": sorted(v["server"]), "ip": sorted(v["ip"]), "last_scan": v["seen"]} for h, v in hosts.items()}
    return sorted(urls), hosts


# ---------------------------------------------------------------- GitHub code search (requiere token)
SECRET_HINT = re.compile(r"(?i)(api[_-]?key|secret|token|passw|client[_-]?secret|authorization|bearer|aws_access|private[_-]?key)")


LIST_HINT = re.compile(r"(?i)(block|adguard|adblock|pihole|hosts|filter|blacklist|whitelist|tracker|domain|ranking|top-?1m|"
                       r"scope|targets?|bounty|dork|wordlist|recon|subdomain|asset|rule|quantumult|surge|clash|shadowrocket|ioc|phish|malware)")


REPO_LIST = re.compile(r"(?i)(block|black|white|adguard|adblock|pihole|hagezi|hosts|filter|tracker|tracking|ranking|top-?1m|"
                       r"inventory|bounty|scope|targets|dork|wordlist|subdomain|ioc|phish|malware|leaks?|privadb|dataset|"
                       r"quantumult|surge|clash|shadowrocket|rule-?script|domain)")


def _is_list_file(it, frags):
    """Repos/ficheros que son LISTAS de dominios (blocklists, scopes de bug bounty, rankings): ruido, no fuga del target."""
    name = (it["repository"]["full_name"] + "/" + it["path"]).lower()
    doms = {registrable(h.lower()) for h in HOST_RE.findall(frags)}
    if len(doms) >= 6:                      # el fragmento cita muchos dominios distintos → es una lista
        return True
    repo = it["repository"]["full_name"].lower()
    if REPO_LIST.search(repo):
        return True
    if LIST_HINT.search(name) and it["path"].rsplit(".", 1)[-1].lower() in ("txt", "csv", "list", "conf", "md", "json", "yaml", "yml", "out", ""):
        return True
    return False


def github(roots, scope, max_pages=2):
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not tok:
        st("github", False, "sin GITHUB_TOKEN en .env (code search lo exige)"); return []
    hdr = {"Authorization": f"Bearer {tok}", "Accept": "application/vnd.github.text-match+json"}
    hits = []
    for root in roots:
        for page in range(1, max_pages + 1):
            q = urllib.parse.quote(f'"{root}"')
            s, d = jget(f"https://api.github.com/search/code?q={q}&per_page=100&page={page}", headers=hdr, timeout=30)
            if d is None:
                st("github", False, f"{root} p{page} http={s}"); break
            items = d.get("items", [])
            for it in items:
                frags = " ".join(m.get("fragment", "") for m in it.get("text_matches", []))
                if _is_list_file(it, frags):
                    continue
                found = sorted({h.lower() for h in HOST_RE.findall(frags) if scope.ok(h.lower())})
                hits.append({"repo": it["repository"]["full_name"], "path": it["path"], "url": it["html_url"],
                             "hosts": found, "secret_hint": bool(SECRET_HINT.search(frags)),
                             "fork": it["repository"].get("fork", False), "owner_type": it["repository"]["owner"].get("type")})
            st("github", True, f"{root} p{page}: {len(items)} ficheros")
            if len(items) < 100:
                break
            time.sleep(7)  # code search: 10 req/min
        time.sleep(7)
    return hits


# ---------------------------------------------------------------- Postman público
def postman(roots, scope):
    out = []
    for root in roots:
        body = {"service": "search", "method": "POST", "path": "/search-all",
                "body": {"queryIndices": ["runtime.collection", "runtime.request", "collaboration.workspace", "adp.api"],
                         "queryText": root, "size": 100, "from": 0, "requestOrigin": "srp", "mergeEntities": True,
                         "nonNestedRequests": True}}
        s, d = jget("https://www.postman.com/_api/ws/proxy", data=body, timeout=40, headers={"Origin": "https://www.postman.com"})
        if d is None:
            st("postman", False, f"{root} http={s}"); continue
        n = 0
        for it in d.get("data", []) or []:
            doc = it.get("document") or {}
            txt = json.dumps(doc)
            hosts = sorted({h.lower() for h in HOST_RE.findall(txt) if scope.ok(h.lower())})
            if not hosts:
                continue
            n += 1
            out.append({"type": doc.get("documentType") or it.get("type"), "name": doc.get("name"),
                        "publisher": doc.get("publisherHandle"), "url": doc.get("url"),
                        "workspaces": [w.get("slug") for w in (doc.get("workspaces") or []) if isinstance(w, dict)],
                        "hosts": hosts, "method": doc.get("method")})
        st("postman", True, f"{root}: {n} elementos públicos que citan hosts en scope")
        time.sleep(2)
    return out


# ---------------------------------------------------------------- JS archivado (archive.org, no el target)
EP_RE = re.compile(r"""["'`](/(?:api|v\d|graphql|rest|internal|admin|auth|oauth|account|user|users|customer|payments?|loan|card|apply|application|merchant|partner)[a-zA-Z0-9_\-/{}.:]*)["'`]""")
URL_IN_JS = re.compile(r"""https?://[a-zA-Z0-9._-]+(?::\d+)?(?:/[a-zA-Z0-9_\-/{}.%:]*)?""")
SECRETS = {
    "aws_access_key": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
    "google_api_key": r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "stripe_live": r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b",
    "stripe_pk_live": r"\bpk_live_[0-9a-zA-Z]{20,}\b",
    "slack_token": r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b",
    "slack_webhook": r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
    "private_key": r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----",
    "jwt": r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "sendgrid": r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
    "twilio": r"\bSK[0-9a-fA-F]{32}\b",
    "mapbox": r"\bsk\.eyJ[A-Za-z0-9_-]+\b",
    "generic_assign": r"(?i)(api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token)\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']",
}
HASHY = re.compile(r"[.\-~][0-9a-f]{6,}(?=\.)", re.I)


def archived_js(js_urls, scope, out_dir: Path, max_files=80, prio_hosts=None):
    """Descarga de archive.org (no del target) la última copia de JS distintos y extrae rutas/URLs/secretos."""
    prio_hosts = prio_hosts or set()
    pick, seen = [], set()
    for u in sorted(js_urls, key=lambda x: (host_of(x) not in prio_hosts, x)):
        h = host_of(u)
        base = HASHY.sub("", urllib.parse.urlparse(u).path.rsplit("/", 1)[-1])
        k = (h, base)
        if k in seen or "jquery" in base.lower() or "gtm" in base.lower() or "analytics" in base.lower():
            continue
        seen.add(k); pick.append(u)
        if len(pick) >= max_files:
            break
    eps, urls, secrets, ok, fail = set(), set(), [], 0, 0
    cache = out_dir / "archived-js" / "files"
    for u in pick:
        s, b = http(f"https://web.archive.org/web/2id_/{u}", timeout=40, tries=2)
        if s != 200 or not b:
            fail += 1; continue
        ok += 1
        txt = b[:4_000_000].decode("utf-8", "replace")
        fn = re.sub(r"[^A-Za-z0-9._-]", "_", u.split("://", 1)[-1])[:150]
        (cache).mkdir(parents=True, exist_ok=True)
        (cache / fn).write_text(txt, encoding="utf-8")
        h = host_of(u)
        for m in EP_RE.findall(txt):
            eps.add(f"{h}\t{m}")
        for m in URL_IN_JS.findall(txt):
            if scope.ok(host_of(m)):
                urls.add(m)
        for name, rx in SECRETS.items():
            for m in re.finditer(rx, txt):
                val = m.group(0)
                secrets.append({"type": name, "file": u, "masked": val[:6] + "…" + val[-4:] if len(val) > 12 else "…"})
        time.sleep(1.5)
    od = out_dir / "archived-js"
    wlines(od / "endpoints.tsv", sorted(eps))
    wlines(od / "in-scope-urls.txt", sorted(urls))
    wjson(od / "secrets.json", secrets)
    st("archived-js", ok > 0 or not pick, f"{ok}/{len(pick)} JS descargados de archive.org · {len(eps)} rutas · {len(urls)} URLs · {len(secrets)} posibles secretos")
    return sorted(eps), sorted(urls), secrets
