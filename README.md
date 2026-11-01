# Atalaya

> *La atalaya otea el horizonte antes de que el vigía suba a la cofa.*

Pipeline OSINT dockerizado para bug bounty. Recopila toda la inteligencia
disponible sobre un target **antes** de lanzar herramientas de recon activo
(VIGÍA). Un solo comando, output estructurado.

**Pipeline:**

```
crt.sh (certificados CT)
  → whois (registro, ASN)
  → dnsrecon (DNS completo)
  → waybackurls (URLs históricas Wayback)
  → gau (URLs de AlienVault + Wayback + Common Crawl + URLScan)
  → whatweb (fingerprinting tecnológico)
  → wafw00f (detección de WAF)
  → theHarvester (emails + subdominios, fuentes libres)
  → [Shodan] (puertos + servicios, opcional con API key)
  → merge + deduplicación + filtrado
```

## Setup

```bash
git clone https://github.com/KarasuJager/atalaya.git
cd atalaya

cp .env.example .env          # opcional: añadir SHODAN_API_KEY
docker compose build          # primera build ~5-8 min
```

## Run

```bash
# pon los dominios root en scope/ (uno por línea)
echo "target.com" > scope/target.txt

# sin Shodan
docker compose run --rm osint /scope/target.txt

# con Shodan
docker compose run --rm osint /scope/target.txt "$SHODAN_API_KEY"
```

## Output

```
data/<programa>/<timestamp>/
├── crtsh/              subdominios de Certificate Transparency
├── whois/              registro de dominio + ASN
├── dns/                DNS records + dnsrecon JSON
├── wayback/            URLs históricas (Wayback Machine)
├── gau/                URLs de múltiples fuentes
├── whatweb/            fingerprinting tecnológico (JSON)
├── wafw00f/            WAF detectado (JSON)
├── theharvester/       emails + subdominios
├── shodan/             puertos + servicios (si API key)
└── merged/
    ├── all-historical-urls.txt    todas las URLs deduplicadas
    ├── interesting-urls.txt       extensiones interesantes (.json, .env, .bak, etc.)
    ├── sensitive-urls.txt         paths sensibles (api, admin, auth, etc.)
    └── all-subdomains.txt         subdominios de todas las fuentes
data/<programa>/latest  ->  symlink a la última run
```

## Herramientas

| Herramienta | Qué hace | API key |
|---|---|---|
| **crt.sh** | Subdominios de Certificate Transparency | No |
| **whois** | Registro de dominio, ASN, rangos IP | No |
| **dnsrecon** | DNS completo: A, MX, TXT, CNAME, zone transfer | No |
| **waybackurls** | URLs históricas del Wayback Machine | No |
| **gau** | URLs de AlienVault OTX + Wayback + Common Crawl + URLScan | No |
| **whatweb** | Fingerprinting de tecnologías web | No |
| **wafw00f** | Detección e identificación de WAF | No |
| **theHarvester** | Emails + subdominios (fuentes libres) | No (módulos básicos) |
| **Shodan** | Puertos y servicios expuestos | Sí (gratis con cuenta) |

## En el flujo AEGIR

```
Atalaya (Fase 1) → OSINTAgent procesa → briefing
  → VIGÍA (Fase 2) → JS analysis → Agentes Tercios → hipótesis
  → Testing (Fase 4) → Validación → Reporte
```

Atalaya corre ANTES de VIGÍA. Su output alimenta al OSINTAgent
(Tercios-agents) que produce un briefing con áreas priorizadas para el recon.

## Responsible use

Solo para **bug bounty autorizado**. Todas las herramientas hacen consultas
pasivas a fuentes públicas. No se envía tráfico activo al target excepto
whatweb y wafw00f (una request HTTP cada uno por dominio root).

---

Built by [Manuel Miguel Fernandez-Gallego Olivares](https://www.linkedin.com/in/manuel-miguel-olivares)
· Offensive Security Engineer · parte del toolkit AEGIR junto a
[VIGÍA](https://github.com/KarasuJager/vigia) (recon activo),
[Huginn](https://github.com/KarasuJager/huginn) (AI pentest) y
[SONDA](https://github.com/KarasuJager/sonda) (differential HTTP testing).
