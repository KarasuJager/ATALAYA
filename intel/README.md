# Atalaya v2 — capa intel ("visión de bounty")

Se ejecuta sola al final de `osint.sh` (paso 9/9). **Todo pasivo**: nada toca el target.

## Qué hace
| Módulo | Fuente | Salida |
|---|---|---|
| `m_history` | wayback+gau ya descargados | `intel/history/` api-routes, specs-and-maps, js-files, config-files, idor-candidates, redirect-params |
| `m_sources.ct` | crt.sh (JSON crudo que guarda osint.sh) | primer/último cert por host, certs frescos (<45 días) |
| `m_sources.dns` | `dig` (resolvedor público) | vivos, CNAMEs, candidatos a takeover (CNAME a servicio + NXDOMAIN) |
| `m_sources.internetdb` | internetdb.shodan.io (sin clave) | puertos, CPEs, CVEs por IP |
| `m_sources.urlscan` | urlscan.io search (clave opcional `URLSCAN_API_KEY`) | hosts/URLs vistos por terceros |
| `m_sources.github` | GitHub code search (**necesita `GITHUB_TOKEN`**) | ficheros públicos que citan hosts en scope |
| `m_sources.postman` | Postman public search | colecciones/workspaces públicos con hosts en scope |
| `m_sources.archived_js` | web.archive.org (copias, no el target) | rutas y secretos (enmascarados) en JS antiguo |
| `m_program` | **bbscope** (con tu sesión → incluye privados) o, si no hay token, bounty-targets-data | scope de la plataforma vs nuestro yaml (targets nuevos / retirados) |
| `m_tools.jsluice` | **jsluice** (BishopFox, análisis AST) sobre JS archivado y código de sourcemaps | `intel/jsluice/` urls.json, paths.txt, params.txt, secrets.json |
| `m_tools.sourcemaps` | **sourcemapper** sobre `.js.map` bajados de archive.org | `intel/sourcemaps/<map>/` código original + `signals.json` (roles, feature flags, rutas internas, entornos) |
| `m_tools.gh_tools` | **github-subdomains** + **github-endpoints** (gwen001) — necesitan `GITHUB_TOKEN` | `intel/github/` subdomains.txt, endpoints.txt |
| `m_tools.trufflehog_github` | **trufflehog** sobre `program.github_orgs` del yaml + repos con señales | `intel/github/trufflehog.json` |
| `m_tools.dockerhub` | Docker Hub API + **trufflehog docker** (imágenes ≤1,5 GB, máx. 6) | `intel/dockerhub/` |
| `m_tools.postman_deep` | **porch-pirate**: workspaces, colecciones y globals públicos | `intel/postman/` |
| `m_tools.chaos` | dataset **Chaos** (ProjectDiscovery) | `intel/chaos-hosts.txt` |
| `m_tools.buckets` | nombres de bucket S3/GCS de la marca — **solo si el programa permite automatización** | `intel/buckets.json` |
| `m_score` | todo lo anterior | `scores.csv/json` 0-100 por host (familias efímeras agrupadas) |
| `m_brief` | todo | `BRIEFING.md` + `hunt-cards.json` (lo leen Capitán y Tercios) |

## Reglas
- Programa con `vps.passive_only: true` o texto "no automation/scanner" en el yaml → osint.sh **no** lanza whatweb ni wafw00f. `wafw00f -a` (payloads) solo con `WAFW00F_ALL=1`.
- Fuente caída ≠ vacío: todo queda en `intel/sources-status.json` y en el briefing. Circuit breaker: 2 fallos de red → se salta la fuente.
- Nada de credenciales de brechas ni OSINT de personas.
- **trufflehog siempre con `--no-verification`**: verificar un secreto es usarlo contra el servicio. Si aparece algo, decide Manu caso a caso.
- Buckets: que exista uno con el nombre de la marca no significa que sea del target. Confirmar propiedad antes de nada.
- `sourcemapper` escribe rutas con `:` (`webpack:/...`), que no valen en NTFS: se extrae en /tmp del contenedor y se copia saneado.

## Campos opcionales en `programs/<p>.yaml`
```yaml
program:
  brands: [acmepay, acmecard]              # marcas extra para Docker Hub/buckets/Postman
  github_orgs: [AcmeBank]                 # orgs a pasar por trufflehog (solo si son del target)
  dockerhub_namespaces: [acmebank]
```

## A mano
```
docker compose run --rm osint /scope/<prog>.txt                  # completo
python3 intel/run.py data/<prog>/<ts> --program-yaml ../../programs/<prog>.yaml --offline   # re-puntuar sin red
```
Variables (.env de ATALAYA): `GITHUB_TOKEN`, `URLSCAN_API_KEY`, `SHODAN_API_KEY`, `HANDLE`, `INTEL_SKIP=github,postman,...`.
