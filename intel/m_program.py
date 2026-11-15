"""Inteligencia del programa: ¿ha cambiado el scope en la plataforma respecto a nuestro yaml? (targets nuevos = menos dups)."""
import json, re, urllib.parse
from common import log, jget, Scope, registrable

BTD = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/{}_data.json"


def _norm(t):
    t = (t or "").strip().lower()
    t = re.sub(r"^https?://", "", t).split("/")[0]
    return t


def scope_drift(prog: dict, platform_targets=None):
    eng = prog.get("engagement") or {}
    plat = (eng.get("platform") or "").lower()
    url = (eng.get("program_url") or "").rstrip("/")
    if plat not in ("bugcrowd", "hackerone", "yeswehack", "intigriti") or not url:
        return {"checked": False, "why": "sin platform/program_url en el yaml"}
    if platform_targets:
        return _compare(prog, {_norm(t) for t in platform_targets if _norm(t)}, "bbscope (sesión: incluye privados)", None, None)
    s, data = jget(BTD.format(plat), timeout=60)
    if data is None:
        return {"checked": False, "why": f"bounty-targets-data http={s}"}
    slug = urllib.parse.urlparse(url).path.rstrip("/").split("/")[-1].lower()
    match = None
    for p in data:
        purl = (p.get("url") or "").lower().rstrip("/")
        if slug and (purl.endswith("/" + slug) or slug in purl):
            match = p; break
    if not match:
        return {"checked": False, "why": f"programa '{slug}' no está en bounty-targets-data (¿privado?)"}
    key = "asset_identifier" if plat == "hackerone" else ("endpoint" if plat == "intigriti" else "target")
    plat_in = {_norm(t.get(key) or t.get("target") or t.get("uri") or t.get("name")) for t in (match.get("targets") or {}).get("in_scope", [])}
    plat_in.discard("")
    return _compare(prog, plat_in, "bounty-targets-data (solo públicos)", match.get("max_payout") or match.get("max_bounty"), match.get("name"))


def _compare(prog, plat_in, source, max_payout, name):
    ours = {_norm(d) for d in ((prog.get("in_scope") or {}).get("domains") or [])}
    # cobertura real, no texto: "*.x.com" en el yaml cubre "x.com"/"a.x.com" de la plataforma
    sample = lambda t: re.sub(r"\*", "x", t).replace("..", ".").strip(".-")
    our_scope = Scope(list(ours), [])
    new = sorted(t for t in plat_in if "." in t and our_scope.status(sample(t)) not in ("in", "apex")
                 and our_scope.status(sample(t).split(".", 1)[-1]) not in ("in", "apex"))
    plat_roots = {registrable(sample(t)) for t in plat_in}
    gone = sorted(t for t in ours if plat_in and registrable(sample(t)) not in plat_roots)
    log(f"program: {len(plat_in)} targets en la plataforma · {len(new)} no están en nuestro yaml · {len(gone)} nuestros ya no aparecen")
    return {"checked": True, "source": source, "platform_targets": sorted(plat_in), "missing_in_yaml": new,
            "not_in_platform": gone, "max_payout": max_payout, "name": name}
