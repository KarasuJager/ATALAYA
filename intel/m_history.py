"""Historial (Wayback/gau/urlscan) → superficie de API olvidada, specs, JS, parámetros con pinta de IDOR.
No toca el target: trabaja sobre las URLs ya recogidas por osint.sh (y las que añadan otros módulos)."""
import re, urllib.parse
from collections import defaultdict, Counter
from common import log, rlines, wjson, wlines, host_of

API_RE = re.compile(r"(?i)/(api|apis|rest|graphql|gql|v[0-9]{1,2}|odata|rpc|services?|ws|backend|internal|_next/data|wp-json)(/|$|\?)")
SPEC_RE = re.compile(r"(?i)(swagger|openapi|api-docs|apidocs|redoc|graphiql|playground|\.wadl|\.wsdl|/docs/api|asyncapi)")
JS_RE = re.compile(r"(?i)\.(m?js)(\?|$)")
MAP_RE = re.compile(r"(?i)\.js\.map(\?|$)")
CFG_RE = re.compile(r"(?i)\.(env|ya?ml|json|xml|config|conf|ini|bak|old|sql|log|zip|tar|gz|7z|rar|pem|key|p12|pfx|csv|xls[x]?)(\?|$)")
STATIC_RE = re.compile(r"(?i)\.(png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|css|mp4|webm|mp3|pdf)(\?|$)")
AUTH_RE = re.compile(r"(?i)(oauth|openid|saml|sso|login|signin|signup|register|reset|forgot|verify|otp|mfa|2fa|token|session|callback|redirect_uri)")
# parámetros con pinta de identificador de objeto → candidatos IDOR (con 2 cuentas)
IDOR_PARAM = re.compile(r"(?i)^(id|ids|uid|user_?id|account_?id|acct|customer_?id|client_?id|order_?id|invoice_?id|"
                        r"application_?id|app_?id|loan_?id|card_?id|contract_?id|doc(ument)?_?id|file_?id|report_?id|"
                        r"payment_?id|transaction_?id|tx_?id|member_?id|profile_?id|org_?id|tenant_?id|merchant_?id|"
                        r"reference|guid|uuid)$")
REDIR_PARAM = re.compile(r"(?i)^(url|uri|next|return|returnurl|return_to|redirect|redirect_uri|redir|continue|dest|destination|goto|target|callback|forward|out|view|to)$")
NUMERIC_SEG = re.compile(r"/\d{2,}(?=/|$)|/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)", re.I)


NOISE_PARAM = re.compile(r"(?i)^(utm_.*|gclid|fbclid|msclkid|_ga|_gl|mc_[a-z]+|swjiylwa|swkmtfsr|ns|cb|xinfo|cinfo|rpinfo|edet|"
                         r"incident_id|mth|_|v|ver|version|cache|cachebuster|t|ts|timestamp|lang|locale|hl|amp;.*)$")


def norm_path(p):
    p = NUMERIC_SEG.sub("/{id}", p)
    return re.sub(r"/+", "/", p) or "/"


def run(urls, scope, out_dir):
    by_host = defaultdict(lambda: {"urls": 0, "api": set(), "specs": set(), "js": set(), "maps": set(), "cfg": set(),
                                   "auth": set(), "idor": set(), "redir": set(), "params": Counter()})
    seen = 0
    for u in urls:
        h = host_of(u)
        if not h or not scope.ok(h):
            continue
        seen += 1
        try:
            pu = urllib.parse.urlparse(u if "://" in u else "http://" + u)
        except Exception:
            continue
        path = pu.path or "/"
        d = by_host[h]
        d["urls"] += 1
        if STATIC_RE.search(path):
            continue
        np_ = norm_path(path)
        if MAP_RE.search(path):
            d["maps"].add(u)
        elif JS_RE.search(path):
            d["js"].add(u.split("#")[0])
        if SPEC_RE.search(u):
            d["specs"].add(u)
        if API_RE.search(path):
            d["api"].add(np_)
        if CFG_RE.search(path):
            d["cfg"].add(u)
        if AUTH_RE.search(path):
            d["auth"].add(np_)
        for k, v in urllib.parse.parse_qsl(pu.query, keep_blank_values=True):
            k2 = k.strip().lower()
            if not k2 or len(k2) > 40:
                continue
            if NOISE_PARAM.match(k2):
                continue
            d["params"][k2] += 1
            if IDOR_PARAM.match(k2):
                d["idor"].add(f"{np_}?{k2}=")
            if REDIR_PARAM.match(k2):
                d["redir"].add(f"{np_}?{k2}=")
        if NUMERIC_SEG.search(path) and API_RE.search(path):
            d["idor"].add(np_)

    hist = {}
    all_api, all_specs, all_js, all_cfg, all_idor, all_redir = [], [], [], [], [], []
    for h, d in sorted(by_host.items()):
        hist[h] = {"urls": d["urls"], "api_routes": len(d["api"]), "specs": len(d["specs"]), "js": len(d["js"]),
                   "sourcemaps": len(d["maps"]), "cfg_files": len(d["cfg"]), "auth_routes": len(d["auth"]),
                   "idor_candidates": len(d["idor"]), "redirect_params": len(d["redir"]),
                   "top_params": [k for k, _ in d["params"].most_common(15)]}
        all_api += [f"https://{h}{p}" for p in sorted(d["api"])]
        all_specs += sorted(d["specs"]); all_js += sorted(d["js"]); all_cfg += sorted(d["cfg"])
        all_idor += [f"https://{h}{p}" for p in sorted(d["idor"])]
        all_redir += [f"https://{h}{p}" for p in sorted(d["redir"])]
        all_specs += sorted(d["maps"])

    od = out_dir / "history"
    wlines(od / "api-routes.txt", all_api)
    wlines(od / "specs-and-maps.txt", all_specs)
    wlines(od / "js-files.txt", all_js)
    wlines(od / "config-files.txt", all_cfg)
    wlines(od / "idor-candidates.txt", all_idor)
    wlines(od / "redirect-params.txt", all_redir)
    wjson(od / "per-host.json", hist)
    log(f"history: {seen} URLs en scope · {len(hist)} hosts · api={len(all_api)} specs/maps={len(all_specs)} "
        f"js={len(all_js)} cfg={len(all_cfg)} idor={len(all_idor)} redir={len(all_redir)}")
    return hist
