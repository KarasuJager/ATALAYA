"""Atalaya v2 — utilidades comunes de la capa de inteligencia (todo pasivo)."""
import json, os, re, time, urllib.request, urllib.error, urllib.parse, ssl
from pathlib import Path

UA = os.environ.get("UA_OVERRIDE") or f"bugbounty-{os.environ.get('HANDLE', 'researcher')}"
LOG_LINES = []

# Sufijos de dos niveles más comunes (para no tratar com.au como "dominio padre")
MULTI_TLD = {"com.au", "net.au", "org.au", "co.nz", "net.nz", "org.nz", "co.uk", "org.uk", "ac.uk", "com.br",
             "com.mx", "co.jp", "ne.jp", "co.in", "co.za", "com.sg", "com.hk", "com.tr", "com.ar", "co.kr", "com.cn"}


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    LOG_LINES.append(line)


def registrable(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_TLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


NET_FAILS = {}   # circuit breaker por host de la fuente: 2 fallos de red completos → no insistir


def http(url, data=None, headers=None, timeout=30, tries=3, method=None):
    """GET/POST con reintentos. Devuelve (status, bytes) o (None, error)."""
    src = urllib.parse.urlsplit(url).hostname or ""
    if NET_FAILS.get(src, 0) >= 2:
        return None, b"circuit-open (fuente inalcanzable)"
    h = {"User-Agent": UA, "Accept": "*/*"}
    h.update(headers or {})
    body = None
    if data is not None:
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        h.setdefault("Content-Type", "application/json")
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, data=body, headers=h, method=method)
            with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
                NET_FAILS[src] = 0
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            if e.code in (429, 502, 503, 504) and i < tries - 1:
                time.sleep(5 * (i + 1)); last = e; continue
            return e.code, e.read() if hasattr(e, "read") else b""
        except Exception as e:  # red, timeout
            last = e
            if i < tries - 1:
                time.sleep(3 * (i + 1))
    NET_FAILS[src] = NET_FAILS.get(src, 0) + 1
    if NET_FAILS[src] == 2:
        log(f"  [!] {src} inalcanzable 2 veces seguidas → se salta el resto de consultas a esa fuente")
    return None, str(last).encode()


def jget(url, **kw):
    st, b = http(url, **kw)
    if st != 200:
        return st, None
    try:
        return st, json.loads(b)
    except Exception:
        return st, None


def wjson(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=1, ensure_ascii=False, sort_keys=False), encoding="utf-8")


def rjson(path: Path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return default


def wlines(path: Path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def rlines(path: Path):
    try:
        return [l.strip() for l in Path(path).read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    except Exception:
        return []


# ---------------------------------------------------------------- scope
def _pat_to_re(p: str):
    p = p.strip().lower().rstrip(".")
    if p.startswith("http"):
        p = urllib.parse.urlparse(p).hostname or p
    esc = re.escape(p).replace(r"\*", r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*")
    return re.compile(rf"^{esc}$")


class Scope:
    """in/out de scope a partir del yaml del programa (aegir-vps/programs/<p>.yaml) o del scope txt.
    Semántica: '*' cubre uno o más labels (también en medio: *.test.*.example-np.com).
    '*.x.com' NO incluye el apex x.com salvo que esté listado (se marca 'apex')."""

    def __init__(self, inc, exc):
        self.inc = [(_p, _pat_to_re(_p)) for _p in inc if _p and _p.strip()]
        self.exc = [(_p, _pat_to_re(_p)) for _p in exc if _p and _p.strip()]
        self.apexes = {p[2:] for p, _ in self.inc if p.startswith("*.")}

    def status(self, host: str) -> str:
        h = (host or "").lower().strip().rstrip(".")
        if not h:
            return "out"
        for _, r in self.exc:
            if r.match(h):
                return "excluded"
        for _, r in self.inc:
            if r.match(h):
                return "in"
        if h in self.apexes:
            return "apex"
        return "out"

    def ok(self, host):
        return self.status(host) in ("in", "apex")


def load_program(yaml_path, scope_txt=None):
    prog = {}
    if yaml_path and Path(yaml_path).exists():
        import yaml
        prog = yaml.safe_load(Path(yaml_path).read_text(encoding="utf-8")) or {}
    inc = list(((prog.get("in_scope") or {}).get("domains")) or [])
    exc = list(((prog.get("out_of_scope") or {}).get("domains")) or [])
    if not inc and scope_txt:
        inc = [l if l.startswith("*") else l for l in rlines(scope_txt) if not l.startswith("#")]
        inc += ["*." + l for l in list(inc) if not l.startswith("*")]
    return prog, Scope(inc, exc)


def passive_only(prog: dict) -> bool:
    """True si el programa prohíbe automatización/escáneres (se lee del yaml)."""
    if (prog.get("vps") or {}).get("passive_only"):
        return True
    txt = json.dumps(prog, ensure_ascii=False).lower()
    return bool(re.search(r"(prohib|forbid|no )[^\"]{0,40}(autom|scanner|escáner|escaner)", txt))


HOST_RE = re.compile(r"(?i)\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b")


def host_of(url: str) -> str:
    try:
        u = url if "://" in url else "http://" + url
        return (urllib.parse.urlparse(u).hostname or "").lower()
    except Exception:
        return ""
