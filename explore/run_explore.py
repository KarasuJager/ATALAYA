#!/usr/bin/env python3
"""Exploradores AEGIR (Capa 1): encuentran lo que las herramientas de recon no ven. El agente propone, la herramienta verifica.

Uso (dentro del contenedor `explore`):
  run_explore.py /data/<programa>/<ts> [--program-yaml /programs/<p>.yaml] [--vigia-js /vigia/<...>/findings/js-raw]
                 [--skip hosts,sinks,routes]
Salida: <run>/explore/  hosts.json · sinks.json · routes.json · EXPLORE.md (y una sección añadida al BRIEFING.md)

- hosts : regulator (patrones de nombres) + subwiz (IA) SIN resolver por su cuenta → scope → DNS solo si el programa
          permite automatización (gate). Lo no resuelto queda "sin confirmar".
- sinks : Semgrep en modo taint (reglas propias de DOM XSS) sobre código de sourcemaps, JS archivado y JS de VIGÍA.
          Cada flujo con fichero:línea. Los flujos entre funciones los sigue el XSSAgent leyendo el código (SemTaint).
- routes: rutas hermanas de las reales (versión, subrecursos de un {id}, singular/plural); "vista en historial" o
          "sin confirmar". Pasivo: no se pide nada al target.
"""
import argparse, concurrent.futures as cf, json, os, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path
sys.path.insert(0, "/app/intel")
from common import load_program, passive_only, registrable, rlines, wlines, wjson, rjson, log, LOG_LINES  # noqa: E402

RULES = Path(__file__).parent / "rules" / "dom-xss.yaml"
REGULATOR = Path("/opt/regulator/main.py")


def run(cmd, timeout=1800, cwd=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "no instalado"


# ------------------------------------------------------------------ hosts
HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$", re.I)


def dig_ok(h):
    """(host, respuestas) — solo IPs reales o CNAME con forma de host. Las líneas de error de dig (';; …') NO cuentan."""
    try:
        r = subprocess.run(["dig", "+time=3", "+tries=2", "+short", "A", h], capture_output=True, text=True, timeout=15)
        lines = [l.strip() for l in r.stdout.splitlines() if l.strip() and not l.startswith(";")]
        ips = [l for l in lines if re.match(r"^\d+\.\d+\.\d+\.\d+$", l)]
        cn = [l.rstrip(".") for l in lines if HOSTNAME.match(l) and not re.match(r"^\d+\.\d+\.\d+\.\d+$", l)]
        return h, ips + [f"CNAME {c}" for c in cn[:1]]
    except Exception:
        return h, []


def verify(out, res, active_ok, threads=8):
    if not active_ok:
        return res
    if not shutil.which("dig"):
        log("[hosts] ⚠ 'dig' no está en el contenedor — no se puede verificar DNS"); return res
    ctrl = next(iter(sorted({registrable(h) for h in res})), None)
    if ctrl:
        c = dig_ok("www." + ctrl)[1] or dig_ok(ctrl)[1]
        log(f"[hosts] control DNS {ctrl}: {'OK ' + str(c[:1]) if c else '⚠ NO resuelve — DNS del contenedor roto, resultados no fiables'}")
    with cf.ThreadPoolExecutor(threads) as ex:
        for h, ans in ex.map(dig_ok, sorted(res)):
            res[h]["resolves"] = bool(ans); res[h]["answer"] = ans[:4]
    return res


def explore_hosts(run_dir, out, scope, active_ok, max_per_tool=120, reverify=False):
    if reverify:
        allc = rjson(out / "hosts.json") or {}
        per, res = {}, {}
        for h, v in allc.items():                       # orden de subwiz = de más a menos probable
            r = registrable(h)
            if per.get(r, 0) < max_per_tool:
                per[r] = per.get(r, 0) + 1; res[h] = v
        res = verify(out, res, active_ok)
        wjson(out / "hosts.json", res)
        wlines(out / "hosts-verified.txt", sorted(h for h, v in res.items() if v["resolves"]))
        log(f"[hosts] re-verificados {len(res)} candidatos · {sum(1 for v in res.values() if v['resolves'])} resuelven")
        return res
    hosts = rjson(run_dir / "intel" / "hosts.json") or {}
    known = sorted(h for h in hosts if "*" not in h)
    if not known:
        log("[hosts] sin hosts.json de intel: ejecuta antes Atalaya"); return {}
    by_root = {}
    for h in known:
        by_root.setdefault(registrable(h), []).append(h)
    cand = {}
    tmp = Path(tempfile.mkdtemp(prefix="exp-"))
    # regulator: necesita ~100 nombres por dominio raíz para aprender patrones útiles
    if "regulator" in os.environ.get("EXPLORE_SKIP", ""):
        log("[hosts] regulator saltado (EXPLORE_SKIP)")
    elif REGULATOR.exists():
        for root, hs in by_root.items():
            if len(hs) < 40:
                continue
            f = tmp / f"{root}.subs"; f.write_text("\n".join(hs), encoding="utf-8")
            # regulator escribe logs/ y <target>.rules en el directorio actual: se lanza en una copia propia
            wd = tmp / "regulator"
            if not wd.exists():
                shutil.copytree(REGULATOR.parent, wd, ignore=shutil.ignore_patterns(".git"))
                (wd / "logs").mkdir(exist_ok=True)
            rc, so, se = run([sys.executable, str(wd / "main.py"), "-t", root, "-f", str(f), "-o", str(tmp / f"{root}.out")],
                             timeout=900, cwd=str(wd))
            got = rlines(tmp / f"{root}.out")[:max_per_tool]
            for g in got:
                cand.setdefault(g.lower(), set()).add("regulator")
            err = "" if rc == 0 else " · error: " + (se or so).strip().splitlines()[-1][:200] if (se or so).strip() else ""
            log(f"[hosts] regulator {root}: {len(hs)} conocidos → {len(got)} candidatos (rc={rc}){err}")
    else:
        log("[hosts] regulator no instalado")
    # subwiz: modelo de IA (local), SIN resolver (la resolución la hacemos nosotros con gate)
    if "subwiz" in os.environ.get("EXPLORE_SKIP", ""):
        log("[hosts] subwiz saltado (EXPLORE_SKIP)")
    elif shutil.which("subwiz"):
        f = tmp / "all.subs"; f.write_text("\n".join(known), encoding="utf-8")
        o = tmp / "subwiz.out"
        rc, so, se = run(["subwiz", "-i", str(f), "-o", str(o), "--no-resolve", "--multi-apex", "-n", str(max_per_tool), "-q"],
                         timeout=2400)
        got = rlines(o)
        for g in got:
            cand.setdefault(g.lower(), set()).add("subwiz")
        log(f"[hosts] subwiz: {len(got)} candidatos (rc={rc}) {se.strip()[:160] if rc else ''}")
    else:
        log("[hosts] subwiz no instalado")
    shutil.rmtree(tmp, ignore_errors=True)
    new = {h: s for h, s in cand.items() if h not in hosts and scope.status(h) in ("in", "apex")}
    res = {h: {"sources": sorted(v), "resolves": None, "answer": []} for h, v in new.items()}
    if active_ok and res:
        res = verify(out, res, active_ok)
        log(f"[hosts] {len(res)} candidatos en scope · {sum(1 for v in res.values() if v['resolves'])} resuelven (DNS)")
    else:
        log(f"[hosts] {len(res)} candidatos en scope · DNS NO comprobado ({'programa sin automatización' if not active_ok else 'nada que comprobar'})")
    wjson(out / "hosts.json", res)
    wlines(out / "hosts-verified.txt", sorted(h for h, v in res.items() if v["resolves"]))
    return res


# ------------------------------------------------------------------ sinks
def _host_from_name(name):
    """VIGÍA guarda 'https___host_ruta.js' → host (y 'gf_https___host_…' para los chunks de getfrontend)."""
    m = re.match(r"^(?:gf_)?https?___([A-Za-z0-9.\-]+?)_", name)
    return m.group(1).lower() if m else ""


# F1 (16-nov): el target sirve SU código desde un CDN (vendappcdn.*.fastly.net, d…cloudfront.net). No es tercero.
CDN_RE = re.compile(r"(cloudfront\.net|fastly\.net|fastlylb\.net|akamaized\.net|akamaihd\.net|edgekey\.net|edgesuite\.net|"
                    r"azureedge\.net|azurefd\.net|b-cdn\.net|cdn77|stackpathcdn|kxcdn|cloudflare-ipfs|r2\.dev|"
                    r"googleusercontent\.com|storage\.googleapis\.com|amazonaws\.com)$", re.I)
THIRD_PARTY_RE = re.compile(r"(google|gstatic|doubleclick|facebook|fbcdn|twitter|segment|sentry|datadog|newrelic|nr-data|hotjar|"
                            r"intercom|zendesk|zdassets|stripe|paypal|cdnjs|jsdelivr|unpkg|jquery|youtube|vimeo|linkedin|tiktok|"
                            r"snapchat|sc-static|optimizely|launchdarkly|amplitude|mixpanel|heap|fullstory|contentsquare|onetrust|"
                            r"cookielaw|recaptcha|hcaptcha|polyfill|bootstrapcdn|fontawesome|typekit|adobe|braze|branch\.io|"
                            r"appsflyer|statsig|raygun|transifex|clarity|bing|hubspot|hs-scripts|marketo|pardot|salesforce|"
                            r"cloudflareinsights|cookiebot|trustarc|usercentrics|wistia|vwo|qualtrics|medallia|pendo|walkme)", re.I)


def first_party_js_hosts(vigia_js, scope):
    """Hosts de CDN que sirven JS a páginas IN-SCOPE del crawl de VIGÍA y no son terceros conocidos → código del target."""
    hosts = set()
    if not vigia_js:
        return hosts
    crawl = Path(vigia_js).parent.parent / "crawl"
    for cf in (crawl.glob("*.json") if crawl.exists() else []):
        try:
            j = json.loads(cf.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        page_host = (re.match(r"https?://([^/:]+)", j.get("url", "")) or [None, ""])[1].lower()
        if not scope or scope.status(page_host) not in ("in", "apex"):
            continue
        for u in (j.get("scripts") or []) + (j.get("resources") or []):
            m = re.match(r"https?://([^/:]+)", u or "")
            h = m.group(1).lower() if m else ""
            if h and u.split("?")[0].endswith((".js", ".mjs")) and CDN_RE.search(h) and not THIRD_PARTY_RE.search(h):
                hosts.add(h)
    return hosts


SMAP_SKIP = re.compile(r"(node_modules|transifex|webpack_bootstrap|webpack_runtime|\(webpack\)|polyfill|core-js|regenerator)", re.I)


def beautify_cached(src: Path, dst: Path):
    """Devuelve (fichero a analizar, 'desminificado'|'original'). Solo desminifica si está minificado (líneas largas)."""
    if dst.exists() and dst.stat().st_size > 0:
        return dst, "desminificado"
    try:
        txt = src.read_text(encoding="utf-8", errors="replace")
        lines = txt.count("\n") + 1
        if len(txt) > 3_000_000 or len(txt) / lines < 300:     # enorme, o ya legible
            return src, "original"
        import jsbeautifier
        o = jsbeautifier.default_options(); o.indent_size = 2
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(jsbeautifier.beautify(txt, o), encoding="utf-8")
        return dst, "desminificado"
    except Exception:
        return src, "original"


TS_SRC = re.compile(r"\.(tsx|ts|jsx)\.js$")


def prepare_js(run_dir, vigia_js, scope, work):
    """Copia a `work` solo el JS que interesa, con extensión .js: sourcemaps (sin node_modules), JS archivado y
    JS de VIGÍA SOLO de hosts en scope (el resto son terceros: Microsoft, HubSpot, analítica…)."""
    work.mkdir(parents=True, exist_ok=True)
    n = {"sourcemaps": 0, "archived": 0, "vigia": 0, "vigia_terceros": 0}
    names = {}                                      # copia en `work` -> fichero real en disco (para citar bien)
    sm = run_dir / "intel" / "sourcemaps"
    for f in (sm.rglob("*") if sm.exists() else []):
        if f.is_file() and "node_modules" not in f.parts and "_maps" not in f.parts and "jsluice" not in f.parts \
                and f.suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".vue"):
            dst = work / "sourcemaps" / f.relative_to(sm)
            dst.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(f, dst); n["sourcemaps"] += 1
    ar = run_dir / "intel" / "archived-js" / "files"
    for f in (ar.iterdir() if ar.exists() else []):
        if f.is_file():
            # F14: corridas antiguas guardaron JS comprimido leído como texto (ilegible): se salta
            head = f.read_text(encoding="utf-8", errors="replace")[:4000]
            if head.count("\ufffd") > 20:
                n["archived_rotos"] = n.get("archived_rotos", 0) + 1; continue
            dname = f.name if f.name.endswith(".js") else f.name + ".js"
            # 9e: el JS archivado viene minificado (snippets de una línea gigante). Se desminifica UNA vez y se guarda
            # en intel/archived-js/beautified/ para que la línea que se cite exista en disco.
            use, copia = beautify_cached(f, ar.parent / "beautified" / f.name)
            if copia == "desminificado":
                n["archived_desminificados"] = n.get("archived_desminificados", 0) + 1
            dst = work / "archived" / dname
            dst.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(use, dst); n["archived"] += 1
            names[f"archived/{dname}"] = {"fichero": str(use.relative_to(run_dir)), "copia": copia}
    n.update({"vigia_cdn": 0, "vigia_smap": 0, "beautified": 0, "ts_original": 0})
    if vigia_js and Path(vigia_js).exists():
        cdn_ok = first_party_js_hosts(vigia_js, scope)
        if cdn_ok:
            log(f"[sinks] CDN del target (sirven JS a páginas en scope, no son terceros): {', '.join(sorted(cdn_ok))}")
        # F2: VIGÍA deja una copia desminificada de cada JS; semgrep va mucho mejor sobre ella (sin timeouts en bundles de 1 MB)
        beaut = Path(vigia_js).parent / "js-analysis" / "beautified"
        for f in Path(vigia_js).iterdir():
            if not f.is_file():
                continue
            h = _host_from_name(f.name)
            kind = None
            if h and scope.status(h) in ("in", "apex"):
                kind = "vigia"
            elif h and h in cdn_ok:
                kind = "vigia_cdn"
            elif f.name.startswith("smap_") and not SMAP_SKIP.search(f.name):
                kind = "vigia_smap"                    # fuente original reconstruido del sourcemap (sin minificar)
            if kind and f.stat().st_size < 6_000_000:
                # F13: fuentes TypeScript/JSX de sourcemaps (VIGÍA las guarda como <x>.tsx.js). Con extensión .js
                # semgrep las lee como JavaScript y da error; y el desminificador las rompe (`<App />` -> `< App / >`).
                # Ya vienen legibles: se usa el ORIGINAL con su extensión real.
                m = TS_SRC.search(f.name)
                if m:
                    use, dname, copia = f, f.name[:-3], "original"
                    n["ts_original"] += 1
                else:
                    src = beaut / f.name
                    use = src if src.exists() and src.stat().st_size > 0 else f
                    copia = "desminificado" if use is src else "original"
                    if use is src:
                        n["beautified"] += 1
                    dname = f.name if f.name.endswith(".js") else f.name + ".js"
                dst = work / "vigia" / dname
                dst.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(use, dst); n[kind] += 1
                names[f"vigia/{dname}"] = {"fichero": f.name, "copia": copia}
            else:
                n["vigia_terceros"] += 1
    log(f"[sinks] JS a analizar: {n['sourcemaps']} de sourcemaps · {n['archived']} archivados"
        f"{' (' + str(n['archived_rotos']) + ' rotos de corridas antiguas, saltados)' if n.get('archived_rotos') else ''}"
        f"{', ' + str(n['archived_desminificados']) + ' desminificados' if n.get('archived_desminificados') else ''} · "
        f"{n['vigia']} de VIGÍA en scope · "
        f"{n['vigia_cdn']} del CDN del target · {n['vigia_smap']} fuentes de sourcemaps ({n['beautified']} desminificados, "
        f"{n['ts_original']} TypeScript/JSX en original) · "
        f"{n['vigia_terceros']} de terceros/librerías descartados")
    return n, names


# Librerías de terceros: sus sinks/listeners no son del target (ej.: ShareThis, flashembed, zone.js…).
LIB_NOISE = ["sharethis", "stlib.", "flashembed", "polyfills", "zone.js", "window-post-message-proxy",
             "http-post-message", "jquery.tools", "swfobject", "_next/static/chunks/pages/signin"]


def explore_sinks(run_dir, out, vigia_js=None, scope=None):
    if not shutil.which("semgrep"):
        log("[sinks] semgrep no instalado"); return []
    work = Path(tempfile.mkdtemp(prefix="sg-"))
    n, names = prepare_js(run_dir, vigia_js, scope, work)
    html = 0
    for f in list(work.rglob("*")):
        try:
            if f.is_file() and f.open("rb").read(200).lstrip()[:1] == b"<":
                f.unlink(); html += 1
        except Exception:
            pass
    if html:
        log(f"[sinks] {html} ficheros eran HTML, no JS (archivados) → descartados")
    if not sum(v for k, v in n.items() if k not in ("vigia_terceros", "beautified")):
        log("[sinks] no hay JS que analizar (sourcemaps, archived-js o VIGÍA en scope)"); return []
    # Por tandas: un bundle enorme ya no tumba todo el análisis (OOM 15-nov con turbopack de Next.js).
    files = sorted(str(f) for f in work.rglob("*") if f.is_file())
    BATCH = int(os.environ.get("EXPLORE_SG_BATCH", "25"))
    d = {"results": [], "errors": []}
    nb = (len(files) + BATCH - 1) // BATCH
    for i in range(0, len(files), BATCH):
        chunk = files[i:i + BATCH]
        cmd = ["semgrep", "--config", str(RULES), "--json", "--metrics=off", "--quiet", "-j", "2",
               "--timeout", os.environ.get("EXPLORE_SG_TIMEOUT", "120"), "--timeout-threshold", "3", "--max-memory", "3000",
               "--max-target-bytes", "3000000", "--no-git-ignore"] + chunk
        rc, so, se = run(cmd, timeout=900)
        try:
            dj = json.loads(so or "{}")
        except Exception:
            dj = {"errors": [{"type": "SalidaIlegible", "message": f"rc={rc} {se[:300]}", "batch": chunk}]}
        d["results"] += dj.get("results", [])
        for e in dj.get("errors", []):
            e.setdefault("batch_first", chunk[0].replace(str(work) + "/", ""))
            d["errors"].append(e)
        log(f"[sinks] tanda {i // BATCH + 1}/{nb}: {len(dj.get('results', []))} resultados · {len(dj.get('errors', []))} errores")
    errs = d.get("errors", [])
    if errs:
        wjson(out / "semgrep-errors.json", errs)
        first = errs[0]
        log(f"[sinks] semgrep: {len(errs)} errores (ver explore/semgrep-errors.json). Primero: "
            f"{str(first.get('type') or first.get('level'))} · {str(first.get('message'))[:200]}")
    found = []
    for r in d.get("results", []):
        path, l0, l1 = r["path"], r["start"]["line"], r["end"]["line"]
        try:
            lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            lines = []
        snippet = "\n".join(lines[max(0, l0 - 1):min(len(lines), l1, l0 + 2)])[:400]
        rule = r["check_id"].split(".")[-1]
        rel = path.replace(str(work) + "/", "")
        nm = names.get(rel)
        if nm:                                       # citar el fichero real (VIGÍA js-raw/beautified o archived-js)
            rel = ("vigia/" + nm["fichero"]) if rel.startswith("vigia/") else nm["fichero"]
        item = {"rule": rule, "file": rel, "line": l0, **({"copia": nm["copia"]} if nm else {}),
                "fuente": (r["extra"].get("metadata") or {}).get("fuente"), "snippet": snippet}
        if rule == "aegir-postmessage-listener":
            body = "\n".join(lines[l0 - 1:min(len(lines), l0 + 40)])
            item["origin_checked"] = bool(re.search(r"\.origin\b", body))
            if item["origin_checked"]:
                item["nota"] = "comprueba event.origin (revisar si la comprobación es débil: indexOf/regex)"
        lib = next((l for l in LIB_NOISE if l in path or l in snippet), None)
        if lib:
            item["ruido_libreria"] = lib
        found.append(item)
    # orden: flujos taint primero, luego listeners sin origin, luego el resto
    rank = lambda i: (3 if i.get("ruido_libreria") else 0 if "to-sink" in i["rule"] else 1 if (i["rule"] == "aegir-postmessage-listener" and not i.get("origin_checked")) else 2)
    found.sort(key=rank)
    shutil.rmtree(work, ignore_errors=True)
    wjson(out / "sinks.json", found)
    real = [f for f in found if not f.get("ruido_libreria")]
    log(f"[sinks] {sum(1 for f in real if 'to-sink' in f['rule'])} flujos fuente→sink · "
        f"{sum(1 for f in real if f['rule']=='aegir-postmessage-listener' and not f.get('origin_checked'))} listeners postMessage sin origin · "
        f"{len(found) - len(real)} de librerías de terceros (al final de sinks.json) · "
        f"errores semgrep: {len(errs)}")
    return found


# ------------------------------------------------------------------ routes
SUBRES = ["documents", "statements", "transactions", "payments", "cards", "accounts", "users", "history", "export",
          "download", "settings", "limits", "applications", "notes", "attachments", "members", "permissions", "roles",
          "invoices", "orders", "refunds", "address", "contacts", "consents", "audit"]
VER = re.compile(r"/v(\d+)(?=/)")
IDSEG = re.compile(r"/(\{id\}|\d{2,}|[0-9a-f]{8}-[0-9a-f-]{27,}|:[a-zA-Z_]+Id|\$\{[^}]+\})(?=/|$)")


SDK = re.compile(r"^/(api/v1/(authn|sessions)|v1/(authorize|token|userinfo|interact|revoke|logout|introspect|keys)|oauth2|idp/|\.well-known/)")
VERBISH = re.compile(r"(?i)(sh|ch|x|ss|us|is|ed|ing|ize|ise|ate|in|out|up|me|status|info|data|config|health|login|logout|"
                     r"refresh|introspect|unlock|verify|validate|search|token|password|authn|authz|authorize|callback|"
                     r"webhook|preferences?|generator|service|bff|checkout)$")


NOISE = re.compile(r"(?i)(\.[a-z0-9]{2,5}$|/wp-(json|content|admin)\b)")   # ficheros estáticos y CMS de marketing


def norm(p):
    return IDSEG.sub("/{id}", p.split("?")[0].rstrip("/"))


def explore_routes(run_dir, out, max_out=400):
    rows = rjson(run_dir / "intel" / "jsluice" / "urls.json") or []
    rows += rjson(run_dir / "intel" / "sourcemaps" / "jsluice" / "urls.json") or []
    paths = set()
    for r in rows:
        u = r.get("url", "")
        p = "/" + u.split("://", 1)[1].split("/", 1)[1] if "://" in u and "/" in u.split("://", 1)[1] else u
        if p.startswith("/") and not SDK.search(p) and re.search(r"(?i)/(api|v\d|bff|service|internal|admin|account|user|customer|merchant|payment|loan|card)", p):
            paths.add(norm(p))
    for u in rlines(run_dir / "intel" / "history" / "api-routes.txt"):
        p = u.split("://", 1)[-1]
        p = "/" + p.split("/", 1)[1] if "/" in p else ""
        if p and not SDK.search(p):
            paths.add(norm(p))
    hist = {norm("/" + u.split("://", 1)[-1].split("/", 1)[1]) for u in rlines(run_dir / "merged" / "all-historical-urls.txt")
            if "://" in u and "/" in u.split("://", 1)[1]}
    cand = {}
    paths = {p for p in paths if not NOISE.search(p)}
    for p in sorted(paths):
        m = VER.search(p)
        if m:
            v = int(m.group(1))
            for nv in {v - 1, v + 1} - {0}:
                cand.setdefault(VER.sub(f"/v{nv}", p, count=1), set()).add(f"versión hermana de {p}")
        if "{id}" in p:
            base = p if p.endswith("{id}") else p[:p.rindex("{id}") + 4]
            for s_ in SUBRES:
                cand.setdefault(f"{base}/{s_}", set()).add(f"subrecurso de {base}")
        last = p.rsplit("/", 1)[-1]
        if last and "{" not in last and re.match(r"^[a-z-]{4,}$", last) and not VERBISH.search(last):
            alt = last[:-1] if last.endswith("s") else last + "s"
            cand.setdefault(p[: -len(last)] + alt, set()).add(f"singular/plural de {p}")
    res = []
    for c, why in cand.items():
        if c in paths:
            continue
        res.append({"route": c, "why": sorted(why)[:2], "seen_in_history": c in hist})
    kind = lambda r: 0 if r["why"][0].startswith("versión") else 1 if r["why"][0].startswith("subrecurso") else 2
    res.sort(key=lambda r: (not r["seen_in_history"], kind(r), r["route"]))
    res = res[:max_out]
    wjson(out / "routes.json", res)
    log(f"[routes] {len(paths)} rutas reales → {len(res)} hermanas ({sum(r['seen_in_history'] for r in res)} vistas en el historial)")
    return res


# ------------------------------------------------------------------ resumen
def summary(out, hosts, sinks, routes, active_ok):
    L = ["## 🔭 Exploradores (Capa 1) — lo que las herramientas no ven", ""]
    if hosts:
        ok = [h for h, v in hosts.items() if v["resolves"]]
        L.append(f"**Hosts deducidos:** {len(hosts)} en scope" + (f", **{len(ok)} resuelven**" if active_ok else " (DNS no comprobado: programa sin automatización)"))
        L += [f"- `{h}` ← {', '.join(hosts[h]['sources'])}" for h in sorted(ok)[:20]] + [""]
    taint = [s for s in sinks if "to-sink" in s["rule"]]
    lst = [s for s in sinks if s["rule"] == "aegir-postmessage-listener" and not s.get("origin_checked")]
    if taint or lst:
        L.append(f"**DOM XSS candidatos:** {len(taint)} flujos fuente→sink · {len(lst)} listeners de postMessage sin `event.origin`")
        L += [f"- {s['fuente']}: `{s['file']}:{s['line']}`" for s in (taint + lst)[:15]] + [""]
    seen = [r for r in routes if r["seen_in_history"]]
    if routes:
        L.append(f"**Rutas hermanas:** {len(routes)} candidatas · {len(seen)} vistas en el historial")
        L += [f"- `{r['route']}` ({r['why'][0]})" for r in seen[:15]] + [""]
    L.append("_Detalle: `explore/hosts.json`, `explore/sinks.json`, `explore/routes.json`. Todo son candidatos: lo prueba Manu._")
    (out / "EXPLORE.md").write_text("\n".join(L), encoding="utf-8")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--program-yaml", default=os.environ.get("PROGRAM_YAML"))
    ap.add_argument("--vigia-js", default=None)
    ap.add_argument("--skip", default=os.environ.get("EXPLORE_SKIP", ""))
    ap.add_argument("--reverify", action="store_true", help="solo re-comprobar el DNS de explore/hosts.json (sin subwiz/regulator)")
    a = ap.parse_args()
    run_dir = Path(a.run_dir)
    out = run_dir / "explore"; out.mkdir(exist_ok=True)
    prog_yaml = a.program_yaml or (f"/programs/{run_dir.parent.name}.yaml" if Path(f"/programs/{run_dir.parent.name}.yaml").exists() else None)
    prog, scope = load_program(prog_yaml, None)
    active_ok = not passive_only(prog) and os.environ.get("ATALAYA_PASSIVE", "0") != "1"
    skip = {x.strip() for x in a.skip.split(",") if x.strip()}
    t0 = time.time()
    log(f"Exploradores · {run_dir.parent.name} · {run_dir.name} · DNS permitido={active_ok}")
    hosts = explore_hosts(run_dir, out, scope, active_ok, reverify=a.reverify) if "hosts" not in skip else {}
    sinks = explore_sinks(run_dir, out, Path(a.vigia_js) if a.vigia_js else None, scope) if "sinks" not in skip else []
    routes = explore_routes(run_dir, out) if "routes" not in skip else []
    txt = summary(out, hosts, sinks, routes, active_ok)
    b = run_dir / "intel" / "BRIEFING.md"
    if b.exists():
        cur = b.read_text(encoding="utf-8")
        cur = cur.split("\n## 🔭 Exploradores")[0].rstrip() + "\n\n" + txt + "\n"
        b.write_text(cur, encoding="utf-8")
        (run_dir / "BRIEFING.md").write_text(cur, encoding="utf-8")
    wlines(out / "explore.log", LOG_LINES)
    log(f"exploradores listos en {int(time.time() - t0)}s → {out}")


if __name__ == "__main__":
    main()
