"""BRIEFING.md + hunt-cards.json: lo que lee Manu por la mañana y lo que consume Tercios (OSINTAgent/Capitán)."""
import json, re, time
from pathlib import Path
from common import wjson

# Rutas que vienen de SDKs de terceros: no son la app del target (y Okta/identidad suele estar fuera de scope)
SDK_ROUTES = {
    "Okta (identidad — suele estar FUERA de scope)": re.compile(r"^/(api/v1/(authn|sessions)|v1/(authorize|token|userinfo|interact|revoke|logout|introspect|keys)|oauth2/?|idp/|\.well-known/)"),
    "Google JS API (ruido)": re.compile(r"^/api/(annotations|earth|language|search|spreadsheets|wave|maps|visualization)/\d"),
}


def sdk_of(path):
    for name, rx in SDK_ROUTES.items():
        if rx.search(path):
            return name
    return ""


CLASS_HINTS = [
    (re.compile(r"(?i)graphql|gql"), "GraphQL: introspección, IDOR por node()/ID, batching"),
    (re.compile(r"(?i)auth|sso|login|oauth|idp|account"), "Auth/cuenta: reset, cambio de email sin re-auth, OAuth redirect_uri, sesión"),
    (re.compile(r"(?i)admin|backoffice|console|internal|manage|ops"), "Control de acceso: rutas de admin con usuario normal, roles"),
    (re.compile(r"(?i)pay|checkout|billing|wallet|loan|apply|card"), "Lógica de negocio: importes, estados, pasos saltables, carreras"),
    (re.compile(r"(?i)merchant|partner|vendor|portal"), "Multi-tenant: IDOR entre comercios/partners con 2 cuentas"),
    (re.compile(r"(?i)api|gateway|gw"), "API: BOLA/IDOR con 2 cuentas, mass assignment, versiones viejas (v1 vs v2)"),
]


# ---------------------------------------------------------------- AEGIR 3.0: dónde probar cada ancla
CDN_CNAME = re.compile(r"(?i)(cloudfront\.net|akamai(edge)?\.net|edgekey\.net|edgesuite\.net|fastly\.net|incapdns\.net|"
                       r"impervadns\.net|cloudflare\.net|cdn\.cloudflare|azureedge\.net|azurefd\.net|footprint\.net|stackpathdns)")
CDN_TECH = re.compile(r"(?i)(cloudflare|incapsula|imperva|akamai|cloudfront|fastly|varnish)")
CDN_IP = ("45.60.", "45.223.", "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "172.64.", "172.67.",
          "23.235.", "151.101.", "199.232.")                               # Imperva, Cloudflare, Fastly (rangos comunes)
SESSION_HOST = re.compile(r"(?i)(^|[.-])(my|account|accounts|portal|servicecentre|service|app|apply|dashboard|customer|"
                          r"client|online|secure|member|merchant|partner|admin|cards?)([.-]|$)")
MONEY = re.compile(r"(?i)(pay|payment|checkout|cart|order|refund|loan|credit|limit|coupon|promo|voucher|reward|points|"
                   r"wallet|balance|transfer|direct-?debit|statement|bank|bff|webhook|callback|apply|application)")
IDISH = re.compile(r"(?i)(\{id\}|/\d{3,}(/|$|\?)|[0-9a-f]{8}-[0-9a-f]{4}-|[?&][a-z_]*id=)")


def host_in(u, final):
    h = u.split("://", 1)[-1].split("/", 1)[0].split("?")[0].lower()
    return h in final or any(k.startswith("*.") and h.endswith(k[1:]) for k in final)


def cdn_of(info):
    for c in info.get("cname") or []:
        if CDN_CNAME.search(c):
            return CDN_CNAME.search(c).group(1)
    for t in info.get("tech") or []:
        if CDN_TECH.search(str(t)):
            return CDN_TECH.search(str(t)).group(1)
    for ip in info.get("ips") or []:
        if ip.startswith(CDN_IP):
            return "CDN (por IP)"
    return ""


def anchors_section(out, final, x):
    """Reparte lo que ya tenemos entre las 4 clases ancla. Todo son candidatos, no hallazgos."""
    from common import rlines, rjson
    jl = x.get("jsluice") or []
    hist_api = rlines(out / "history" / "api-routes.txt")
    idor_hist = rlines(out / "history" / "idor-candidates.txt")
    urls = [r["url"] for r in jl] + hist_api
    noise = lambda u: bool(re.search(r"(?i)(\.(html?|js|css|png|jpe?g|svg|pdf)(\?|$)|/wp-(json|content|admin)\b|#)", u))
    sdk = lambda u: noise(u) or bool(sdk_of(u if u.startswith("/") else ("/" + u.split("://", 1)[-1].split("/", 1)[-1] if "/" in u.split("://", 1)[-1] else "")))
    A = {}
    # IDOR
    idor = [u for u in dict.fromkeys(idor_hist + [u for u in urls if IDISH.search(u)])
            if not sdk(u) and (u.startswith("/") or (u.startswith("http") and host_in(u, final)))]
    idor.sort(key=lambda u: (not re.search(r"(?i)(dev|test|uat|stag|sandbox|-np)", u), not re.search(r"(?i)/(api|v\d)", u)))
    exp_routes = rjson(out.parent / "explore" / "routes.json") or []
    idor += [f"{r['route']} (deducida: {r['why'][0]})" for r in exp_routes if "{id}" in r.get("route", "")][:4]
    A["IDOR / BOLA"] = (idor[:8], "rutas con IDs vistas sin sesión (pocas a propósito: los IDs buenos salen con sesión → "
                                  "tráfico de A y B con traffic_to_flow). Probar con cuentas A y B (ficha 1)")
    # Business logic
    money = [u for u in dict.fromkeys(u for u in urls if MONEY.search(u) and not sdk(u))]
    money.sort(key=lambda u: (not re.search(r"(?i)(dev|test|uat|stag|sandbox|-np)", u), not re.search(r"(?i)(bff|webhook|callback|limit|refund)", u)))
    orgs = x.get("github_org_candidates") or []
    A["Business logic"] = (money[:8] + [f"código público: github.com/{o}" for o in orgs[:3]],
                           "procesos de dinero/crédito: hacerlos enteros con A y B en Burp → traffic_to_flow (ficha 2)")
    # WCD
    wcd = []
    dangling = {t["host"] for t in (x.get("dangling") or [])}
    for h, info in final.items():
        if "*" in h or info.get("dns") == "dead" or h in dangling:
            continue
        c = cdn_of(info)
        if c and SESSION_HOST.search(h):
            wcd.append(f"{h} — detrás de {c}")
    wcd.sort(key=lambda s: (not re.search(r"(?i)(dev|test|uat|stag|sandbox|-np)", s), s))
    A["Web cache deception"] = (wcd[:8], "área de cliente detrás de CDN: probar /cuenta/x.css con y sin sesión (ficha 3)")
    # DOM XSS
    dom = []
    for d in (x.get("sourcemaps") or []):
        if d.get("own_files"):
            sig = (x.get("source_signals") or {}).get(d["map"]) or {}
            dom.append(f"{d['map']} → {d['own_files']} ficheros de código original" + (f" · señales: {', '.join(sig)}" if sig else ""))
    sinks = rjson(out.parent / "explore" / "sinks.json") or []
    taint = [s_ for s_ in sinks if "to-sink" in s_.get("rule", "")]
    lst = [s_ for s_ in sinks if s_.get("rule") == "aegir-postmessage-listener" and not s_.get("origin_checked")]
    dom = [f"{s_['fuente']} → sink en `{s_['file']}:{s_['line']}`" for s_ in taint[:5]] + \
          [f"postMessage sin event.origin en `{s_['file']}:{s_['line']}`" for s_ in lst[:3]] + dom
    if not taint and not lst:
        dom.append("· los exploradores aún no han corrido o no han encontrado flujos (ver sección Exploradores)")
    A["DOM XSS"] = (dom[:8], "seguir fuente→sink en el navegador y confirmar con DOM Invader (ficha 4)")
    L = ["## 🎯 Dónde probar cada ancla", "",
         "_Lo que ya tenemos, repartido entre las 4 clases. Candidatos, no hallazgos: cada uno se trabaja con su ficha._", ""]
    for name, (items, how) in A.items():
        L.append(f"### {name} — {len(items)} sitios por donde empezar")
        L.append(f"_{how}_")
        L += [f"- {i[2:]}" if i.startswith("· ") else f"- `{i}`" if not i.startswith("código público") and "→" not in i and "—" not in i else f"- {i}"
              for i in items] or ["- (nada claro en los datos de esta corrida)"]
        L.append("")
    return L


def hint(host, info):
    out = [msg for rx, msg in CLASS_HINTS if rx.search(host)]
    hi = info.get("hist") or {}
    if hi.get("specs") or hi.get("sourcemaps"):
        out.insert(0, "Leer spec/sourcemap: rutas ocultas y parámetros reales")
    if hi.get("idor_candidates"):
        out.append(f"{hi['idor_candidates']} rutas con IDs en historial → probar con 2 cuentas")
    if info.get("takeover"):
        out.insert(0, "Takeover: confirmar a mano el CNAME colgando")
    return out[:3] or ["Mapear funcionalidad con cuenta y buscar flujos multi-paso"]


def accounts(host, info):
    hi = info.get("hist") or {}
    if hi.get("auth_routes") or re.search(r"(?i)login|account|portal|app|merchant|partner", host):
        return "probable registro/login → crear 2 cuentas (A/B) con @bugcrowdninja/@wearehackerone"
    return ""


def write(run, out, pname, prog, ponly, rows, final, new_hosts, fresh, hist, tko, gh, pm, js_eps, js_secrets, drift, prev_dir, status, x=None):
    x = x or {}
    L = []
    L.append(f"# BRIEFING — {pname} · {run.name}")
    L.append(f"_Atalaya v3 · generado {time.strftime('%Y-%m-%d %H:%M')} · todo pasivo · hipótesis, no hallazgos_\n")
    warn = []
    if ponly:
        warn.append("**PROGRAMA SIN AUTOMATIZACIÓN**: solo módulos pasivos; VIGÍA/nuclei/arcabuz NO.")
    eng_ai = (prog.get("ai_policy") or {})
    if eng_ai.get("agents_allowed") in (False, "no"):
        warn.append("Política de IA del programa: agentes NO permitidos.")
    for r in (prog.get("out_of_scope") or {}).get("rules", []) or []:
        warn.append(r)
    agg = {}
    for sx in status:
        a = agg.setdefault(sx["source"], {"ok": 0, "fail": 0, "last": ""})
        a["ok" if sx["ok"] else "fail"] += 1
        a["last"] = sx["info"]
    failed = [k for k, v in agg.items() if v["fail"] and not v["ok"]]
    partial = [k for k, v in agg.items() if v["fail"] and v["ok"]]
    if failed:
        warn.append("Fuentes caídas (vacío ≠ sin datos): " + ", ".join(failed))
    if partial:
        warn.append("Fuentes con fallos parciales: " + ", ".join(partial))
    # F6 (16-nov): estado de las fuentes del paso OSINT (Wayback, gau, theHarvester) — antes no se miraba aquí
    hist_failed, hist_trunc = [], []
    stf = Path(run) / "merged" / "_sources-status.txt"
    for line in (stf.read_text(encoding="utf-8", errors="replace").splitlines() if stf.exists() else []):
        parts = [x.strip() for x in line.split("|")]
        if len(parts) < 3:
            continue
        h, src, st = parts[0], parts[1], parts[2]
        if st.startswith("FAILED"):
            hist_failed.append(f"{src} en `{h}`")
        elif "TRUNCADO" in st:
            n = (re.match(r"ok (\d+)", st) or [None, "?"])[1]
            hist_trunc.append(f"{src} en `{h}` ({n} URLs, cortado en el tope)")
    if hist_failed:
        warn.append("Historial INCOMPLETO — fuentes caídas (vacío ≠ sin historial, no concluir nada): " + ", ".join(hist_failed))
    if hist_trunc:
        warn.append("Historial TRUNCADO — hay más de lo que vemos (se completó solo con parámetros, /api/ y .js): " + ", ".join(hist_trunc))
    if warn:
        L.append("## ⚠ Avisos\n" + "\n".join(f"- {w}" for w in warn) + "\n")

    if drift.get("checked") and drift.get("missing_in_yaml"):
        L.append(f"## 🆕 Scope de la plataforma que NO está en nuestro yaml _(fuente: {drift.get('source','')})_\n" +
                 "\n".join(f"- `{t}`" for t in drift["missing_in_yaml"][:30]) +
                 (("\n\nEn nuestro yaml pero ya no en la plataforma (¿retirados? confirmar antes de testear):\n" +
                   "\n".join(f"- `{t}`" for t in drift.get("not_in_platform", [])[:30])) if drift.get("not_in_platform") else "") +
                 "\n\n→ Revisar en la web del programa y añadir al yaml si es real (targets nuevos = menos dups).\n")

    try:
        L += anchors_section(out, final, x)
    except Exception as e:                                  # el briefing nunca se cae por esta sección
        L.append(f"_(sección de anclas no disponible: {e})_\n")
    L.append("## 🎯 Top 10 — dónde mirar primero\n")
    L.append("| # | Host | Score | Por qué | Qué probar | Cuentas |")
    L.append("|---|---|---|---|---|---|")
    cards = []
    for i, r in enumerate(rows[:10], 1):
        info = final[r["host"]]
        hs = hint(r["host"], info)
        acc = accounts(r["host"], info)
        fam = f" ({info['family_size']} hosts)" if info.get("family_size") else ""
        L.append(f"| {i} | `{r['host']}`{fam} | {r['score']} | {'; '.join(s.split(' ',1)[1] for s in r['signals'][:4])} | {hs[0]} | {acc or '—'} |")
        cards.append({"host": r["host"], "score": r["score"], "signals": r["signals"], "try": hs, "accounts": acc,
                      "hist": info.get("hist"), "dns": info.get("dns"), "ips": info.get("ips"), "ports": info.get("ports"),
                      "vulns": info.get("vulns"), "tech": info.get("tech"), "examples": info.get("examples", [])})
    L.append("")
    if prev_dir is None:
        L.append("_Primera corrida con intel: no hay diff contra la anterior todavía._\n")
    if new_hosts:
        L.append(f"## 🆕 Nuevo desde la corrida anterior ({prev_dir.name if prev_dir else '—'}): {len(new_hosts)} hosts\n" +
                 "\n".join(f"- `{h}`" for h in new_hosts[:25]) + ("\n- …" if len(new_hosts) > 25 else "") + "\n")
    if fresh:
        L.append(f"## 🌱 Certificados recién emitidos ({len(fresh)}) — superficie que casi nadie ha visto\n" +
                 "\n".join(f"- `{h}` (1er cert {final.get(h,{}).get('first_cert','')})" for h in fresh[:25]) + "\n")
    if tko:
        L.append("## 🪝 Takeover candidatos (confirmar a mano; en non-prod puede ser solo informativo)\n" +
                 "\n".join(f"- `{t['host']}` → `{t['cname']}` ({t['service']}, {t['cname_status']})" for t in tko) + "\n")
    dg = x.get("dangling") or []
    if dg:
        L.append("## 🔌 DNS colgando (NO tomable hoy: el proveedor exige probar control del dominio) — informativo\n" +
                 "\n".join(f"- `{t['host']}` → `{t['cname']}` ({t['service']}, {t['cname_status']})" for t in dg) +
                 "\n\n→ Solo vale si se demuestra toma real. CloudFront pide certificado ACM del dominio: no reportar como takeover.\n")
    specs = []
    sm = out / "history" / "specs-and-maps.txt"
    if sm.exists():
        specs = [l for l in sm.read_text(encoding="utf-8").splitlines() if l][:20]
    if specs:
        L.append("## 📜 Specs / sourcemaps en el historial (leer antes de nada)\n" + "\n".join(f"- {s}" for s in specs) + "\n")
    sm = x.get("sourcemaps") or []
    if sm:
        L.append(f"## 🗺️ Código original reconstruido desde sourcemaps ({len(sm)}) — leer esto primero\n")
        for d in sm[:10]:
            L.append(f"- `{d['map']}` → `intel/{d['dir']}` ({d['own_files']} ficheros propios)")
            for k, v in (x.get("source_signals", {}).get(d["map"]) or {}).items():
                L.append(f"  - **{k}** ({len(v)}): " + "; ".join(f"`{i}`" for i in v[:3]))
        L.append("")
    jl = x.get("jsluice") or []
    if jl:
        path_of = lambda u: ("/" + u.split("://", 1)[-1].split("/", 1)[1]) if "://" in u and "/" in u.split("://", 1)[-1] else u
        sdk = {}
        for r in jl:
            n = sdk_of(path_of(r["url"]))
            if n:
                sdk.setdefault(n, []).append(r["url"])
        own = [r for r in jl if not sdk_of(path_of(r["url"]))]
        api = [r for r in own if re.search(r"(?i)/(api|v\d|graphql|rest|internal|admin|account|user|customer|merchant|partner|bff|payment|direct-debit|bank)", path_of(r["url"]))]
        L.append(f"## 🧬 Rutas y parámetros reales sacados del JS con jsluice ({len(jl)} · {len(api)} de API)\n" +
                 "\n".join(f"- `{(r['method'] + ' ') if r['method'] else ''}{r['url']}`" +
                           (f" · query: {', '.join(r['query'][:6])}" if r['query'] else "") +
                           (f" · body: {', '.join(r['body'][:6])}" if r['body'] else "") for r in api[:30]) + "\n" +
                 "".join(f"\n_Apartadas por ser de SDK de terceros — {k}: {len(v)} rutas (p. ej. `{v[0]}`)_\n" for k, v in sdk.items()))
    if js_eps:
        L.append(f"## 🧩 Rutas sacadas de JS archivado ({len(js_eps)})\n" + "\n".join(f"- `{e}`" for e in js_eps[:30]) + "\n")
    if js_secrets:
        L.append(f"## 🔑 Posibles secretos en JS archivado ({len(js_secrets)}) — verificar si siguen vivos SIN usarlos contra terceros\n" +
                 "\n".join(f"- {s['type']} `{s['masked']}` en {s['file']}" +
                           (" · _parece clave pública de Google (Maps/JS API): casi nunca paga_" if re.search(r"(?i)jsapi|maps|google", s['file']) or str(s['masked']).startswith('AIza') else "")
                           for s in js_secrets[:15]) + "\n")
    th = (x.get("trufflehog") or []) + (x.get("docker_secrets") or []) + [
        {"source": "jsluice", "detector": z.get("kind"), "masked": z.get("masked"), "where": {"file": z.get("file")}} for z in (x.get("jsluice_secrets") or [])]
    if th:
        L.append(f"## 🐷 Posibles secretos (trufflehog/jsluice) — {len(th)} · SIN verificar a propósito: no usar contra terceros; decide Manu caso a caso\n" +
                 "\n".join(f"- [{z['source']}] {z.get('detector')} `{z.get('masked')}` {json.dumps(z.get('where', {}), ensure_ascii=False)[:160]}" for z in th[:20]) + "\n")
    oc = x.get("github_org_candidates") or []
    if oc:
        L.append("## 🏢 Organizaciones de GitHub que parecen de la marca (confirmar y añadir a `program.github_orgs`)\n" +
                 "\n".join(f"- [`{o}`](https://github.com/{o})" for o in oc) +
                 "\n\n→ Si es oficial, en la próxima corrida trufflehog revisa la org entera (historial incluido).\n")
    dc = x.get("docker_cands") or {}
    if dc:
        L.append(f"## 🐳 Imágenes Docker Hub de la marca ({len(dc)})\n" + "\n".join(
            f"- `{k}` · pulls {v.get('pulls')} {'· declarada en yaml' if v.get('declared') else '· por nombre (confirmar que es suya)'}" for k, v in list(dc.items())[:15]) + "\n")
    pw = x.get("postman_ws") or []
    if pw:
        L.append(f"## 📮 Workspaces públicos de Postman con hosts en scope ({len(pw)})\n" + "\n".join(
            f"- [{w['name']}]({w['link']}) → {', '.join(w['hosts'][:4])} · colecciones: {len(w['collections'])}"
            + (f" · ⚠ {len(w['globals_sensitive'])} variables sensibles" if w['globals_sensitive'] else "") for w in pw[:15]) + "\n")
    ge = x.get("gh_endpoints") or []
    if ge:
        L.append(f"## 🐙 Endpoints citados en GitHub (github-endpoints) — {len(ge)}\n" + "\n".join(f"- `{e}`" for e in ge[:20]) + "\n")
    bk = [b for b in (x.get("buckets") or [])]
    if bk:
        L.append("## 🪣 Buckets que existen con nombre de la marca (que exista ≠ que sea suyo: confirmar propiedad antes de nada)\n" +
                 "\n".join(f"- {b['provider']} `{b['name']}` → {b['status']}{' · LISTABLE' if b['listable'] else ''}" for b in bk[:20]) + "\n")
    if gh or pm:
        L.append("## 🐙 Fugas públicas (GitHub / Postman)\n" +
                 "\n".join(f"- GitHub `{g['repo']}` {g['path']} → {', '.join(g['hosts'][:4])}{' · ⚠ pinta de secreto' if g['secret_hint'] else ''}" for g in gh[:15]) +
                 ("\n" if gh else "") +
                 "\n".join(f"- Postman {p['type']} \"{p['name']}\" ({p['publisher']}) → {', '.join(p['hosts'][:4])}" for p in pm[:15]) + "\n")
    idor = out / "history" / "idor-candidates.txt"
    if idor.exists() and idor.stat().st_size:
        L.append("## 🔢 Rutas con IDs en el historial (candidatas a IDOR con 2 cuentas)\n" +
                 "\n".join(f"- {l}" for l in idor.read_text(encoding='utf-8').splitlines()[:20]) + "\n")
    L.append("## Fuentes\n" + "\n".join(f"- {k}: {v['ok']} ok / {v['fail']} fallos — {v['last']}" for k, v in agg.items()) + "\n")
    L.append("Ficheros: `intel/scores.csv`, `intel/hosts.json`, `intel/hunt-cards.json`, `intel/history/*`, `intel/archived-js/*`, `intel/leaks.json`, `intel/infra.json`.")
    (out / "BRIEFING.md").write_text("\n".join(L), encoding="utf-8")
    (run / "BRIEFING.md").write_text("\n".join(L), encoding="utf-8")
    wjson(out / "hunt-cards.json", cards)
