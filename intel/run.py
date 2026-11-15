#!/usr/bin/env python3
"""Atalaya v2 — capa de inteligencia "visión de bounty".
Uso: run.py <run_dir> [--program-yaml P] [--scope-txt S] [--offline] [--skip mod1,mod2]
Todo pasivo: no envía tráfico al target. Deja <run_dir>/intel/ + BRIEFING.md."""
import argparse, json, os, re, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from common import log, LOG_LINES, rlines, wlines, wjson, rjson, load_program, passive_only, registrable, host_of
import m_history, m_sources, m_score, m_program, m_brief, m_tools


def prev_intel(run_dir: Path):
    runs = sorted([p for p in run_dir.parent.iterdir() if p.is_dir() and p.name[:8].isdigit() and p.name < run_dir.name])
    for p in reversed(runs):
        h = rjson(p / "intel" / "hosts.json")
        if h:
            return p, h
    # sin intel previo: usar subdominios de la corrida anterior como referencia
    for p in reversed(runs):
        subs = rlines(p / "merged" / "all-subdomains.txt")
        if subs:
            return p, {"__fallback__": True, **{s: {} for s in subs}}
    return None, {}


EPHEMERAL = re.compile(r"^(?:[0-9a-f]{10,}|\d{1,4}|[0-9a-f]{6,}-[0-9a-f-]+|pr-?\d+|preview-[\w-]+)$")


def collapse(final):
    """Agrupa hosts efímeros (hash/num/pr-N como primera etiqueta) en familias '*.resto'."""
    fam = {}
    for h, v in final.items():
        lab, _, rest = h.partition(".")
        if rest and EPHEMERAL.match(lab):
            # colapsa también varios niveles efímeros (abc123.001.dev.x → *.dev.x)
            while True:
                l2, _, r2 = rest.partition(".")
                if r2 and EPHEMERAL.match(l2):
                    rest = r2
                else:
                    break
            fam.setdefault("*." + rest, []).append((h, v))
    out = {h: v for h, v in final.items()}
    for fk, members in fam.items():
        if len(members) < 3:
            continue
        for h, _ in members:
            out.pop(h, None)
        agg = dict(members[0][1])
        agg["family_size"] = len(members)
        agg["examples"] = [h for h, _ in members[:5]]
        agg["new"] = all(v["new"] for _, v in members)
        agg["fresh_cert"] = any(v["fresh_cert"] for _, v in members)
        agg["takeover"] = next((v["takeover"] for _, v in members if v["takeover"]), "")
        agg["js_secrets"] = sum(v["js_secrets"] for _, v in members)
        agg["dns"] = "alive" if any(v["dns"] == "alive" for _, v in members) else members[0][1]["dns"]
        for k in ("ports", "vulns", "tech", "sources", "ips"):
            agg[k] = sorted({x for _, v in members for x in v.get(k, [])})[:30]
        hist = {}
        for _, v in members:
            for k2, n in (v.get("hist") or {}).items():
                if isinstance(n, (int, float)):
                    hist[k2] = hist.get(k2, 0) + n
        agg["hist"] = hist
        out[fk] = agg
    return out


def diversify(rows, n=10, per_service=2):
    """Top-N sin que un mismo servicio (etiqueta 'servicio' antes del dominio raíz) acapare."""
    seen, top, rest = {}, [], []
    for r in rows:
        parts = r["host"].lstrip("*.").split(".")
        svc = ".".join(parts[-3:]) if len(parts) >= 3 else r["host"]
        if seen.get(svc, 0) < per_service:
            seen[svc] = seen.get(svc, 0) + 1
            top.append(r)
        else:
            rest.append(r)
        if len(top) == n:
            break
    return top + [r for r in rows if r not in top]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--program-yaml", default=os.environ.get("PROGRAM_YAML"))
    ap.add_argument("--scope-txt")
    ap.add_argument("--offline", action="store_true", help="solo lo que ya hay en disco (sin fuentes de red)")
    ap.add_argument("--skip", default=os.environ.get("INTEL_SKIP", ""))
    ap.add_argument("--fresh-days", type=int, default=45)
    a = ap.parse_args()
    run = Path(a.run_dir)
    out = run / "intel"; out.mkdir(exist_ok=True)
    os.environ["INTEL_OUT"] = str(out)
    skip = {s.strip() for s in a.skip.split(",") if s.strip()}
    t0 = time.time()

    prog, scope = load_program(a.program_yaml, a.scope_txt)
    pname = run.parent.name
    ponly = passive_only(prog)
    log(f"Atalaya intel · {pname} · run {run.name} · passive_only={ponly}")
    roots = sorted({registrable(p.lstrip("*.").replace("*.", "").split("*")[-1].lstrip("-.")) for p, _ in scope.inc} |
                   {l for l in rlines(a.scope_txt) if not l.startswith("#")} if a.scope_txt else
                   {registrable(p.lstrip("*.").split("*")[-1].lstrip("-.")) for p, _ in scope.inc})
    roots = sorted(r for r in roots if "." in r)
    log(f"dominios raíz: {', '.join(roots)}")

    # ---- universo de hosts
    hosts = {}
    def touch(h, src):
        h = h.lower().strip().rstrip(".")
        if not h or "*" in h:
            return None
        stt = scope.status(h)
        if stt not in ("in", "apex"):
            return None
        e = hosts.setdefault(h, {"sources": set(), "scope": stt})
        e["sources"].add(src)
        return e

    for f in (run / "crtsh").glob("*.txt"):
        for h in rlines(f):
            touch(h, "crtsh")
    for h in rlines(run / "merged" / "all-subdomains.txt"):
        touch(h, "harvester")

    # ---- historial
    urls = rlines(run / "merged" / "all-historical-urls.txt")
    extra_urls = []

    # ---- fuentes de red
    ct_hosts, fresh, dnsr, ips, tko, idb, us_urls, us_hosts, gh, pm, drift = {}, [], {}, {}, [], {}, [], {}, [], [], {}
    x = {"gh_endpoints": [], "postman_ws": [], "jsluice": [], "jsluice_secrets": [], "sourcemaps": [], "source_signals": {},
         "trufflehog": [], "docker_cands": {}, "docker_secrets": [], "buckets": []}
    active_ok = not ponly and os.environ.get("ATALAYA_PASSIVE", "0") != "1"
    brand_list = m_tools.brands(roots, prog)
    if not a.offline:
        if "ct" not in skip:
            ct_hosts, fresh = m_sources.ct(roots, scope, run / "crtsh", a.fresh_days)
            for h in ct_hosts: touch(h, "crtsh")
        if "urlscan" not in skip:
            us_urls, us_hosts = m_sources.urlscan(roots, scope)
            for h in us_hosts: touch(h, "urlscan")
            extra_urls += us_urls
        if "github" not in skip:
            gh = m_sources.github(roots, scope)
            for g in gh:
                for h in g["hosts"]: touch(h, "github")
        if "postman" not in skip:
            pm = m_sources.postman(roots, scope)
            for p in pm:
                for h in p["hosts"]: touch(h, "postman")
        if "program" not in skip:
            bb = m_tools.bbscope_targets(prog) if "bbscope" not in skip else None
            drift = m_program.scope_drift(prog, bb)
        if "chaos" not in skip:
            for h in m_tools.chaos(prog, roots, scope, out): touch(h, "chaos")
        if "ghtools" not in skip:
            x_gh_subs, x["gh_endpoints"] = m_tools.gh_tools(roots, scope, out)
            for h in x_gh_subs: touch(h, "github-subdomains")
            extra_urls += [e for e in x["gh_endpoints"] if e.startswith("http")]
        if "postman" not in skip:
            x["postman_ws"] = m_tools.postman_deep(roots, scope, out, pm_hits=pm)
            for w in x["postman_ws"]:
                for h in w["hosts"]: touch(h, "postman")
    hist = m_history.run(urls + extra_urls, scope, out)
    for h in hist: touch(h, "history")

    if not a.offline and "dns" not in skip:
        dnsr, ips, tko = m_sources.dns(list(hosts))
        if "internetdb" not in skip:
            idb = internetdb = m_sources.internetdb(ips)

    js_eps, js_urls, js_secrets = [], [], []
    if not a.offline and "archivedjs" not in skip:
        prio = {h for h in hosts if m_score.HOT.search(h) or m_score.NONPROD.search(h)}
        js_eps, js_urls, js_secrets = m_sources.archived_js(rlines(out / "history" / "js-files.txt") +
                                                             [u for u in rlines(out / "history" / "specs-and-maps.txt") if u.endswith(".js")],
                                                             scope, out, prio_hosts=prio)
        for u in js_urls: touch(host_of(u), "archived-js")

    # ---- JS a fondo: jsluice (AST) + código original desde sourcemaps archivados
    if not a.offline and "sourcemaps" not in skip:
        maps = [u for u in rlines(out / "history" / "specs-and-maps.txt") if u.split("?")[0].endswith(".map")]
        x["sourcemaps"] = m_tools.sourcemaps(maps, out)
        for d in x["sourcemaps"]:
            sig = m_tools.source_signals(out / d["dir"])
            if sig:
                x["source_signals"][d["map"]] = sig
        wjson(out / "sourcemaps" / "signals.json", x["source_signals"])
    if "jsluice" not in skip:
        rows_a, sec_a = m_tools.jsluice(out / "archived-js" / "files", scope, out) if (out / "archived-js" / "files").exists() else ([], [])
        rows_b, sec_b = ([], [])
        if (out / "sourcemaps").exists():
            rows_b, sec_b = m_tools.jsluice(out / "sourcemaps", scope, out / "sourcemaps")
        x["jsluice"], x["jsluice_secrets"] = rows_a + rows_b, sec_a + sec_b
        for r in x["jsluice"]:
            if r["url"].startswith("http"): touch(host_of(r["url"]), "jsluice")

    # ---- fugas: trufflehog en GitHub (orgs del yaml + repos con señales) y Docker Hub — SIN verificar secretos
    pr0 = prog.get("program") or {}
    if not a.offline and "trufflehog" not in skip:
        orgs = list(pr0.get("github_orgs") or [])
        # orgs candidatas = dueños de repos cuyo nombre contiene la marca (p. ej. AcmeBankOSS); se SUGIEREN,
        # solo se escanean enteras si están en el yaml (github_orgs). Repos sueltos: solo de esas orgs candidatas.
        cand_orgs = sorted({g["repo"].split("/")[0] for g in gh if any(b in g["repo"].split("/")[0].lower() for b in brand_list)})
        x["github_org_candidates"] = [o for o in cand_orgs if o not in orgs]
        repos = sorted({g["repo"] for g in gh if g["repo"].split("/")[0] in cand_orgs and not g.get("fork")})
        x["trufflehog"] = m_tools.trufflehog_github(orgs, repos, out)
    if not a.offline and "dockerhub" not in skip:
        x["docker_cands"], x["docker_secrets"] = m_tools.dockerhub(brand_list, list(pr0.get("dockerhub_namespaces") or []), out)
    if not a.offline and "buckets" not in skip:
        x["buckets"] = m_tools.buckets(brand_list, out, active_ok)

    # ---- tecnologías (whatweb si existe) y WAF
    tech = {}
    for f in (run / "whatweb").glob("*.json"):
        try:
            for e in json.loads(f.read_text(encoding="utf-8", errors="replace") or "[]"):
                h = host_of(e.get("target", ""))
                tech.setdefault(h, set()).update((e.get("plugins") or {}).keys())
        except Exception:
            pass

    # ---- ensamblar por host
    prev_dir, prev = prev_intel(run)
    dangling = [t for t in tko if t["service"] in m_sources.NOT_TAKEABLE]
    tko = [t for t in tko if t["service"] not in m_sources.NOT_TAKEABLE]
    x["dangling"] = dangling
    take = {t["host"]: f'{t["service"]} ({t["cname"]})' for t in tko}
    sec_by_host = {}
    for s_ in js_secrets:
        sec_by_host[host_of(s_["file"])] = sec_by_host.get(host_of(s_["file"]), 0) + 1
    final = {}
    for h, e in hosts.items():
        d = dnsr.get(h) or {}
        ip_list = d.get("a", [])
        ports, vulns, cpes = set(), set(), set()
        for ip in ip_list:
            ix = idb.get(ip) or {}
            ports |= set(ix.get("ports") or []); vulns |= set(ix.get("vulns") or []); cpes |= set(ix.get("cpes") or [])
        third = {"urlscan", "github", "github-subdomains", "postman", "archived-js", "jsluice", "chaos"}
        hidden = sorted(e["sources"] & third) if not (e["sources"] & {"crtsh", "harvester"}) else []
        final[h] = {
            "scope": e["scope"], "sources": sorted(e["sources"]),
            "new": bool(prev) and not prev.get("__fallback__") and h not in prev,
            "first_cert": (ct_hosts.get(h) or {}).get("first_cert", ""),
            "fresh_cert": h in fresh,
            "hidden": hidden,
            "dns": ("alive" if (d.get("a") or d.get("cname")) else "dead") if dnsr else "unknown",
            "cname": d.get("cname", []), "ips": ip_list,
            "ports": sorted(ports), "vulns": sorted(vulns)[:20], "tech": sorted(tech.get(h, set()) | cpes),
            "hist": hist.get(h, {}), "takeover": take.get(h, ""), "js_secrets": sec_by_host.get(h, 0),
        }
    wjson(out / "hosts.json", final)
    final = collapse(final)

    pr = prog.get("program") or {}
    ctx = {"known_dups_text": " ".join(pr.get("known_dups") or []) + " " + str(pr.get("notes", ""))}
    rows = diversify(m_score.score_all(final, ctx))
    m_score.write(rows, out)

    wjson(out / "leaks.json", {"github": gh, "postman": pm, "postman_workspaces": x["postman_ws"], "js_secrets": js_secrets,
                               "jsluice_secrets": x["jsluice_secrets"], "trufflehog": x["trufflehog"],
                               "docker": x["docker_secrets"], "buckets": x["buckets"]})
    wjson(out / "infra.json", {"internetdb": idb, "takeover_candidates": tko, "urlscan_hosts": us_hosts})
    wjson(out / "program.json", drift)
    wjson(out / "sources-status.json", m_sources.STATUS)
    new_hosts = sorted(h for h, v in final.items() if v["new"])
    wlines(out / "new-hosts.txt", new_hosts)
    wlines(out / "fresh-cert-hosts.txt", sorted(fresh))

    m_brief.write(run, out, pname, prog, ponly, rows, final, new_hosts, fresh, hist, tko, gh, pm, js_eps, js_secrets, drift,
                  prev_dir, m_sources.STATUS, x)
    log(f"intel listo en {int(time.time()-t0)}s → {out}  · hosts={len(final)} nuevos={len(new_hosts)} frescos={len(fresh)}")
    wlines(out / "intel.log", LOG_LINES)


if __name__ == "__main__":
    main()
