"""Atalaya v3 — herramientas externas (todas pasivas salvo buckets, que va con gate).
jsluice · sourcemapper · github-subdomains/endpoints · trufflehog (git/github/docker) · porch-pirate · bbscope · Chaos · buckets.
Cada una: si el binario/clave no está, se marca en sources-status y se sigue (nunca rompe la corrida)."""
import io, json, os, re, shutil, subprocess, tempfile, time, urllib.parse, zipfile
from pathlib import Path
from common import log, http, jget, wjson, wlines, rlines, host_of, registrable, HOST_RE, Scope
from m_sources import st

UA_TOOL = os.environ.get("HANDLE", "researcher")


def have(b):
    return shutil.which(b) is not None


def run(cmd, timeout=600, env=None, cwd=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env={**os.environ, **(env or {})}, cwd=cwd)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or ""), "timeout"
    except FileNotFoundError:
        return 127, "", "no instalado"


def brands(roots, prog):
    """Marcas para buscar en Docker Hub/buckets/Postman: 'acmebank.com.au' → 'acmebank'."""
    b = {registrable(r).split(".")[0] for r in roots}
    b |= set(((prog.get("program") or {}).get("brands")) or [])
    return sorted(x.lower() for x in b if len(x) >= 4)


def _mask(v):
    v = str(v)
    return v[:6] + "…" + v[-4:] if len(v) > 14 else "…"


# ------------------------------------------------------------- 1. jsluice (AST) sobre ficheros JS en disco
def jsluice(js_dir: Path, scope: Scope, out_dir: Path, base_url_of=None):
    files = [p for p in js_dir.rglob("*") if p.is_file() and p.suffix in (".js", ".mjs", ".ts", ".tsx", ".jsx", ".vue", "")
             and p.stat().st_size < 8_000_000 and not ({"node_modules", "_maps", "jsluice"} & set(p.parts))]
    if not files:
        return [], []
    if not have("jsluice"):
        st("jsluice", False, "binario no instalado (se usan las regex de respaldo)"); return [], []
    urls, secrets = {}, []
    for chunk in [files[i:i + 200] for i in range(0, len(files), 200)]:
        rc, so, se = run(["jsluice", "urls", "-u", "-f", "-c", "4", *map(str, chunk)], timeout=900)
        for line in so.splitlines():
            try:
                j = json.loads(line)
            except Exception:
                continue
            u = j.get("url", "")
            if not u or u.startswith(("data:", "blob:")) or len(u) > 400:
                continue
            if u.startswith("//"):
                u = "https:" + u
            first = u.split("/", 1)[0]
            if not u.startswith(("http", "/")) and re.match(r"^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?$", first, re.I):
                u = "https://" + u          # 'sharethis.com/api/x' sin esquema → tratar como URL absoluta
            h = host_of(u) if u.startswith("http") else ""
            if h and not scope.ok(h):
                continue
            k = (u, j.get("method", ""))
            e = urls.setdefault(k, {"url": u, "method": j.get("method") or "", "type": j.get("type", ""),
                                    "query": sorted(set(j.get("queryParams") or [])), "body": sorted(set(j.get("bodyParams") or [])),
                                    "files": set()})
            e["files"].add(Path(j.get("filename", "")).name)
        rc, so, se = run(["jsluice", "secrets", "-f", "-c", "4", *map(str, chunk)], timeout=900)
        for line in so.splitlines():
            try:
                j = json.loads(line)
            except Exception:
                continue
            d = j.get("data") or {}
            val = d.get("key") or d.get("value") or d.get("secret") or json.dumps(d)[:60]
            secrets.append({"kind": j.get("kind"), "severity": j.get("severity"), "file": Path(j.get("filename", "")).name,
                            "masked": _mask(val)})
    rows = sorted(({**v, "files": sorted(v["files"])[:5]} for v in urls.values()), key=lambda x: x["url"])
    od = out_dir / "jsluice"; od.mkdir(parents=True, exist_ok=True)
    wjson(od / "urls.json", rows); wjson(od / "secrets.json", secrets)
    wlines(od / "paths.txt", sorted({r["url"] for r in rows if r["url"].startswith("/")}))
    wlines(od / "params.txt", sorted({p for r in rows for p in r["query"] + r["body"]}))
    st("jsluice", True, f"{len(files)} ficheros · {len(rows)} URLs/rutas · {len(secrets)} posibles secretos")
    return rows, secrets


# ------------------------------------------------------------- 2. sourcemapper: código original desde .js.map archivados
def sourcemaps(map_urls, out_dir: Path, max_maps=25):
    od = out_dir / "sourcemaps"
    if not map_urls:
        return []
    if not have("sourcemapper"):
        st("sourcemapper", False, "binario no instalado"); return []
    done = []
    for u in map_urls[:max_maps]:
        s, b = http(f"https://web.archive.org/web/2id_/{u}", timeout=60, tries=2)
        if s != 200 or not b or not b.lstrip().startswith(b"{"):
            continue
        slug = re.sub(r"[^A-Za-z0-9._-]", "_", u.split("://", 1)[-1])[:120]
        raw = od / "_maps" / (slug + ".map"); raw.parent.mkdir(parents=True, exist_ok=True); raw.write_bytes(b)
        dst = od / slug
        # sourcemapper escribe rutas tipo "webpack:/src/..." → ':' no vale en NTFS (data/ es carpeta de Windows).
        # Se extrae en /tmp del contenedor y se copia con nombres saneados.
        tmp = Path(tempfile.mkdtemp(prefix="sm-"))
        rc, so, se = run(["sourcemapper", "-url", str(raw), "-output", str(tmp / "o")], timeout=180)
        for f in (tmp / "o").rglob("*") if (tmp / "o").exists() else []:
            if f.is_file():
                rel = [re.sub(r'[<>:"|?*\\]', "_", part).strip(" .") or "_" for part in f.relative_to(tmp / "o").parts]
                t = dst.joinpath(*rel); t.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copyfile(f, t)
                except OSError:
                    pass
        shutil.rmtree(tmp, ignore_errors=True)
        n = sum(1 for p in dst.rglob("*") if p.is_file()) if dst.exists() else 0
        if n:
            # descarta node_modules: interesa el código propio
            own = [p for p in dst.rglob("*") if p.is_file() and "node_modules" not in p.parts
                   and not any(x in str(p) for x in ("webpack_bootstrap", "(webpack)", "webpack/runtime"))]
            done.append({"map": u, "dir": str(dst.relative_to(out_dir)), "files": n, "own_files": len(own),
                         "sample": sorted(str(p.relative_to(dst)) for p in own)[:15]})
        time.sleep(1.5)
    wjson(od / "index.json", done)
    st("sourcemapper", True, f"{len(done)}/{min(len(map_urls), max_maps)} sourcemaps reconstruidos · {sum(d['own_files'] for d in done)} ficheros propios")
    return done


def source_signals(src_root: Path):
    """Grep dirigido sobre el código reconstruido: lo que un cazador mira primero."""
    pats = {
        "roles/permisos": r"(?i)\b(isAdmin|is_admin|role\s*[=:]|roles?\.(includes|indexOf)|hasPermission|canAccess|permission[s]?\b)",
        "feature flags": r"(?i)(featureFlag|feature_flag|launchdarkly|isEnabled\(|flags?\.[a-z]+Enabled)",
        "rutas internas": r"[\"'`](/(?:internal|admin|debug|test|staff|ops|backoffice|v\d+/admin)[A-Za-z0-9_\-/{}:.]*)",
        "entornos": r"https?://[a-z0-9.-]*(?:dev|test|uat|stg|staging|sandbox|qa|np)[a-z0-9.-]*\.[a-z.]{2,}",
        "ids en rutas": r"[\"'`]/[A-Za-z0-9_\-/]*/(?:\$\{[^}]+\}|:[a-zA-Z]+Id)\b",
    }
    hits = {k: [] for k in pats}
    for p in src_root.rglob("*"):
        if not p.is_file() or "node_modules" in p.parts or p.suffix not in (".js", ".ts", ".tsx", ".jsx", ".vue", ".json"):
            continue
        try:
            t = p.read_text(encoding="utf-8", errors="replace")[:2_000_000]
        except Exception:
            continue
        for k, rx in pats.items():
            for m in re.finditer(rx, t):
                if len(hits[k]) < 60:
                    hits[k].append(f"{p.relative_to(src_root)}: {m.group(0)[:120]}")
    return {k: v for k, v in hits.items() if v}


# ------------------------------------------------------------- 3. GitHub: github-subdomains / github-endpoints / trufflehog
def gh_tools(roots, scope: Scope, out_dir: Path):
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    od = out_dir / "github"; od.mkdir(parents=True, exist_ok=True)
    subs, eps = set(), set()
    if not tok:
        st("github-subdomains", False, "sin GITHUB_TOKEN"); st("github-endpoints", False, "sin GITHUB_TOKEN"); return [], []
    for tool, acc in (("github-subdomains", subs), ("github-endpoints", eps)):
        if not have(tool):
            st(tool, False, "binario no instalado"); continue
        for r in roots:
            f = od / f"{tool}-{r}.txt"
            rc, so, se = run([tool, "-d", r, "-t", tok, "-k", "-raw", "-o", str(f)], timeout=900)
            got = rlines(f) or [l for l in so.splitlines() if l.strip()]
            for l in got:
                l = l.strip()
                h = host_of(l) if "://" in l else l.lower().split("/")[0]
                if scope.ok(h):
                    acc.add(l if tool == "github-endpoints" else h)
            time.sleep(2)
        st(tool, True, f"{len(acc)} en scope")
    wlines(od / "subdomains.txt", sorted(subs)); wlines(od / "endpoints.txt", sorted(eps))
    return sorted(subs), sorted(eps)


TH_NOISE_PATH = re.compile(r"(?i)(/usr/(local/)?lib/|/var/lib/dpkg|site-packages/|dist-info/|node_modules/|/vendor/|\.so(\.\d+)*$|__pycache__|/tests?/|\.min\.js$|/usr/share/)")
TH_NOISE_DET = {"URI", "Box", "RedHatPyxis", "PrivateKey"}   # en rutas de sistema/librerías son siempre falsos positivos


def _th_lines(so, src):
    out = []
    for line in so.splitlines():
        try:
            j = json.loads(line)
        except Exception:
            continue
        meta = j.get("SourceMetadata", {}).get("Data", {})
        loc = next(iter(meta.values()), {}) if meta else {}
        fpath = str(loc.get("file") or "")
        if TH_NOISE_PATH.search(fpath) or (j.get("DetectorName") in TH_NOISE_DET and not fpath.startswith(("/app", "/srv", "/opt", "/home", "/etc"))):
            continue
        out.append({"source": src, "detector": j.get("DetectorName"), "verified": j.get("Verified", False),
                    "masked": _mask(j.get("Raw", "")), "where": {k: loc.get(k) for k in ("repository", "file", "commit", "line", "link", "image", "layer") if loc.get(k)}})
    return out


def trufflehog_github(orgs, repos, out_dir: Path, max_repos=12):
    """Secretos en repos públicos. SIN verificación: verificar = usar la credencial contra el servicio."""
    if not (orgs or repos):
        return []
    if not have("trufflehog"):
        st("trufflehog-github", False, "binario no instalado"); return []
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    found = []
    for org in orgs:
        cmd = ["trufflehog", "github", f"--org={org}", "--no-verification", "--json", "--no-update", "--concurrency=4"]
        if tok:
            cmd.append(f"--token={tok}")
        rc, so, se = run(cmd, timeout=1800)
        found += _th_lines(so, f"github-org:{org}")
    for r in repos[:max_repos]:
        rc, so, se = run(["trufflehog", "git", f"https://github.com/{r}", "--no-verification", "--json", "--no-update"], timeout=600)
        found += _th_lines(so, f"github-repo:{r}")
    wjson(out_dir / "github" / "trufflehog.json", found)
    st("trufflehog-github", True, f"{len(orgs)} orgs · {min(len(repos), max_repos)} repos · {len(found)} posibles secretos (sin verificar)")
    return found


# ------------------------------------------------------------- 7. Docker Hub: descubrir imágenes + trufflehog docker
def dockerhub(brand_list, namespaces, out_dir: Path, max_images=6, max_gb=1.5):
    od = out_dir / "dockerhub"; od.mkdir(parents=True, exist_ok=True)
    cands = {}
    for ns in namespaces:
        s, d = jget(f"https://hub.docker.com/v2/repositories/{ns}/?page_size=50", timeout=30)
        for r in (d or {}).get("results", []) or []:
            cands[f"{ns}/{r['name']}"] = {"namespace": ns, "name": r["name"], "pulls": r.get("pull_count"),
                                          "updated": r.get("last_updated"), "declared": True}
    for b in brand_list:
        s, d = jget(f"https://hub.docker.com/v2/search/repositories/?query={urllib.parse.quote(b)}&page_size=50", timeout=30)
        for r in (d or {}).get("results", []) or []:
            ns = r.get("repo_owner") or (r.get("repo_name", "").split("/")[0])
            full = r.get("repo_name") if "/" in r.get("repo_name", "") else f"{ns}/{r.get('repo_name')}"
            # solo si la marca está en el namespace (no en cualquier imagen que la mencione)
            # estricto: el namespace ES la marca o empieza por ella ('blackgemfinance' no es 'gemfinance')
            nsl = (ns or "").lower()
            if (nsl == b or re.match(rf"^{re.escape(b)}[-_]?[a-z]*$", nsl)) and full not in cands:
                cands[full] = {"namespace": ns, "name": full.split("/", 1)[-1], "pulls": r.get("pull_count"),
                               "updated": None, "declared": False}
    wjson(od / "candidates.json", cands)
    found = []
    if cands and have("trufflehog"):
        scanned = 0
        for full, c in sorted(cands.items(), key=lambda kv: (not kv[1]["declared"], -(kv[1]["pulls"] or 0))):
            if scanned >= max_images:
                break
            s, t = jget(f"https://hub.docker.com/v2/repositories/{full}/tags/?page_size=1&ordering=last_updated", timeout=30)
            tag = ((t or {}).get("results") or [{}])[0]
            if not tag.get("name") or (tag.get("full_size") or 0) > max_gb * 1e9:
                continue
            rc, so, se = run(["trufflehog", "docker", f"--image={full}:{tag['name']}", "--no-verification", "--json", "--no-update"], timeout=1500)
            found += _th_lines(so, f"docker:{full}:{tag['name']}")
            scanned += 1
        st("dockerhub", True, f"{len(cands)} imágenes candidatas · {scanned} analizadas · {len(found)} posibles secretos (sin verificar)")
    else:
        st("dockerhub", True, f"{len(cands)} imágenes candidatas" + ("" if have("trufflehog") else " · trufflehog no instalado"))
    wjson(od / "trufflehog.json", found)
    return cands, found


# ------------------------------------------------------------- 4. Postman a fondo (porch-pirate)
def postman_deep(roots, scope: Scope, out_dir: Path, max_ws=15):
    od = out_dir / "postman"; od.mkdir(parents=True, exist_ok=True)
    try:
        from porchpirate import porchpirate
        pp = porchpirate()
    except Exception as e:
        st("porch-pirate", False, f"no instalado ({e})"); return []
    wss, reqs = {}, []
    for r in roots:
        try:
            d = json.loads(pp.search(r) or "{}")
        except Exception as e:
            st("porch-pirate", False, f"{r}: {e}"); continue
        for it in d.get("data", []) or []:
            doc = it.get("document") or {}
            t = doc.get("documentType") or it.get("documentType")
            txt = json.dumps(doc)
            hosts = sorted({h.lower() for h in HOST_RE.findall(txt) if scope.ok(h.lower())})
            if not hosts:
                continue
            for w in doc.get("workspaces") or []:
                if w.get("id"):
                    wss.setdefault(w["id"], {"name": w.get("name"), "hosts": set()})["hosts"].update(hosts)
            if t == "request":
                reqs.append({"name": doc.get("name"), "method": doc.get("method"), "url": doc.get("url"), "hosts": hosts,
                             "publisher": (doc.get("publisherHandle") or "")})
        time.sleep(2)
    detail = []
    for wid, w in list(wss.items())[:max_ws]:
        g, env_secrets = {}, []
        try:
            g = json.loads(pp.workspace_globals(wid) or "{}")
        except Exception:
            pass
        vals = (g.get("data") or {}).get("values") or []
        for v in vals:
            k, val = v.get("key", ""), str(v.get("value", ""))
            if val and re.search(r"(?i)token|secret|key|pass|auth|bearer|cookie|session", k):
                env_secrets.append({"key": k, "masked": _mask(val)})
        cols = []
        try:
            c = json.loads(pp.collections(wid) or "{}")
            cols = [x.get("name") for x in (c.get("data") or [])][:30]
        except Exception:
            pass
        detail.append({"workspace": wid, "name": w["name"], "hosts": sorted(w["hosts"]), "globals_sensitive": env_secrets,
                       "collections": cols, "link": f"https://www.postman.com/workspace/{wid}"})
        time.sleep(1.5)
    wjson(od / "workspaces.json", detail); wjson(od / "requests.json", reqs)
    st("porch-pirate", True, f"{len(detail)} workspaces · {len(reqs)} peticiones públicas con hosts en scope · "
       f"{sum(len(d['globals_sensitive']) for d in detail)} variables sensibles")
    return detail


# ------------------------------------------------------------- 5. bbscope: scope real de la plataforma (incluye privados)
BB_PLAT = {"hackerone": "h1", "bugcrowd": "bc", "intigriti": "it", "yeswehack": "ywh"}


def bbscope_targets(prog):
    eng = prog.get("engagement") or {}
    plat = BB_PLAT.get((eng.get("platform") or "").lower())
    url = (eng.get("program_url") or "").rstrip("/").lower()
    if not plat or not url:
        return None
    if not have("bbscope"):
        st("bbscope", False, "binario no instalado"); return None
    args = ["bbscope", "poll", plat, "-o", "tcu", "-d", "\t", "--oos"]
    tk = {"h1": ("BBSCOPE_H1_TOKEN", "--token"), "bc": ("BBSCOPE_BC_TOKEN", "--token"),
          "it": ("BBSCOPE_IT_TOKEN", "--token"), "ywh": ("BBSCOPE_YWH_TOKEN", "--token")}[plat]
    if not os.environ.get(tk[0]):
        st("bbscope", False, f"sin {tk[0]} en .env (sin sesión no ve privados; se usa bounty-targets-data)"); return None
    args += [tk[1], os.environ[tk[0]]]
    if plat == "h1":
        args += ["--user", os.environ.get("BBSCOPE_H1_USER", "")]
    rc, so, se = run(args, timeout=900)
    slug = urllib.parse.urlparse(url).path.rstrip("/").split("/")[-1]
    tg = []
    for line in so.splitlines():
        oos = line.startswith("[OOS] ")          # bbscope marca así lo fuera de scope con --oos
        p = line[6:].split("\t") if oos else line.split("\t")
        if len(p) >= 3 and slug and slug in p[-1].lower():
            tg.append({"target": p[0], "category": p[1], "url": p[-1], "oos": oos})
    st("bbscope", rc == 0, f"{len(tg)} targets del programa '{slug}' (rc={rc})")
    wjson(Path(os.environ.get("INTEL_OUT", "/tmp")) / "bbscope-targets.json", tg)
    return [t["target"] for t in tg if not t["oos"] and t["category"].lower() in ("url", "wildcard", "other", "")] or None


# ------------------------------------------------------------- 6. Chaos (ProjectDiscovery) — dataset público
def chaos(prog, roots, scope: Scope, out_dir: Path):
    s, idx = jget("https://chaos-data.projectdiscovery.io/index.json", timeout=60)
    if idx is None:
        st("chaos", False, f"index http={s}"); return []
    url = ((prog.get("engagement") or {}).get("program_url") or "").lower().rstrip("/")
    slug = url.split("/")[-1] if url else ""
    picks = []
    for p in idx:
        purl = (p.get("program_url") or "").lower().rstrip("/")
        name = (p.get("name") or "").lower().replace(" ", "")
        toks = {registrable(r).split(".")[0] for r in roots}
        toks = {t for t in toks if len(t) >= 5}
        if (slug and (purl.endswith("/" + slug) or slug.replace("-", "") == name)) or any(t == name or name.startswith(t) for t in toks):
            picks.append(p)
    hosts = set()
    for p in picks[:5]:
        s, b = http(p.get("URL") or p.get("url") or "", timeout=120)
        if s != 200:
            continue
        try:
            z = zipfile.ZipFile(io.BytesIO(b))
            for n in z.namelist():
                for l in z.read(n).decode("utf-8", "replace").splitlines():
                    l = l.strip().lower()
                    if l and scope.ok(l):
                        hosts.add(l)
        except Exception:
            pass
    wlines(out_dir / "chaos-hosts.txt", sorted(hosts))
    st("chaos", True, f"{len(picks)} programas casan en Chaos ({', '.join(p.get('name','') for p in picks[:3])}) · {len(hosts)} hosts en scope")
    return sorted(hosts)


# ------------------------------------------------------------- extra: buckets (GATE: solo si el programa permite automatización)
BK_SUFFIX = ["", "-dev", "-test", "-staging", "-stg", "-uat", "-prod", "-backup", "-backups", "-assets", "-static",
             "-uploads", "-media", "-files", "-data", "-logs", "-public", "-private", "-internal", "-np"]


def buckets(brand_list, out_dir: Path, active_ok: bool):
    if not active_ok:
        st("buckets", True, "omitido: el programa no permite automatización"); return []
    names = sorted({b + s for b in brand_list for s in BK_SUFFIX})[:200]
    res, dead, tried = [], {}, 0
    for n in names:
        for prov, u in (("s3", f"https://{n}.s3.amazonaws.com/"), ("gcs", f"https://storage.googleapis.com/{n}/")):
            if dead.get(prov, 0) >= 3:          # 3 fallos de red seguidos en un proveedor → se abandona ese proveedor
                continue
            s, b = http(u, timeout=15, tries=1, method="GET")
            tried += 1
            if s is None:
                dead[prov] = dead.get(prov, 0) + 1; continue
            dead[prov] = 0
            if s in (200, 403):
                listable = s == 200 and (b"<ListBucketResult" in (b or b"") or b'"items"' in (b or b""))
                res.append({"provider": prov, "name": n, "status": s, "listable": listable, "url": u})
            time.sleep(0.3)
    wjson(out_dir / "buckets.json", res)
    down = [p for p, v in dead.items() if v >= 3]
    st("buckets", not down, (f"proveedores inalcanzables: {', '.join(down)} · " if down else "") + f"{len(names)} nombres probados · {len(res)} existen · {sum(r['listable'] for r in res)} listables (¡ojo: que exista ≠ que sea del target!)")
    return res
