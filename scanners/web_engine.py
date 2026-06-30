import re
import math
import json
import hashlib
import requests
from datetime import datetime
from urllib.parse import urljoin, urlparse

SECRET_PATTERNS = [
    (r'AIza[0-9A-Za-z\-_]{35}',                                                              "Google/Gemini API Key"),
    (r'(?i)GEMINI[_-]?KEY\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})',                           "Gemini API Key"),
    (r'(?i)OPENAI[_-]?API[_-]?KEY\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})',                   "OpenAI API Key"),
    (r'sk-[A-Za-z0-9]{32,}',                                                                 "OpenAI SK Key"),
    (r'(?i)(aws_access_key_id)\s*[=:]\s*["\']?([A-Z0-9]{20})',                              "AWS Access Key"),
    (r'(?i)(aws_secret_access_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})',                    "AWS Secret Key"),
    (r'(?i)(api[_-]?key|apikey)\s*[=:"\']{1,3}([A-Za-z0-9_\-]{20,})',                      "API Key"),
    (r'(?i)(secret[_-]?key|app[_-]?secret)\s*[=:"\']{1,3}([A-Za-z0-9_\-]{20,})',           "Secret Key"),
    (r'(?i)(jwt[_-]?secret|jwt[_-]?key)\s*[=:"\']{1,3}([^\s"\'\\]{10,})',                  "JWT Secret"),
    # Password pattern - requires non-trivial value (not JS false/boolean)
    (r'(?i)(?:^|[\s,;{(])(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\'\\]{8,})["\']',       "Password"),
    (r'(?i)(token|access_token|auth_token)\s*[=:"\']{1,3}([A-Za-z0-9_\-\.]{20,})',         "Auth Token"),
    (r'(?i)(stripe[_-]?(?:key|secret))\s*[=:"\']{1,3}([A-Za-z0-9_\-]{20,})',               "Stripe Key"),
    (r'(?i)(db_pass(?:word)?|database_password)\s*[=:"\']{1,3}([^\s"\'\\&]{8,})',           "DB Password"),
    (r'mongodb(?:\+srv)?://[^\s"\'<>\n\\]+',                                                 "MongoDB URI"),
    (r'postgres(?:ql)?://[^\s"\'<>\n\\]+',                                                   "PostgreSQL URI"),
    (r'mysql://[^\s"\'<>\n\\]+',                                                             "MySQL URI"),
    (r'redis://[^\s"\'<>\n\\]+',                                                             "Redis URI"),
    (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',                                   "PEM Private Key"),
    (r'(?i)(supabase[_-]?(?:key|url|anon))\s*[=:"\']{1,3}([A-Za-z0-9_\-\.]{20,})',         "Supabase Key"),
    (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',                 "JWT Token"),
    (r'NEXT_PUBLIC_[A-Z_]+["\s]*:["\s]*["\']([A-Za-z0-9_\-\.:/]{10,})["\']',               "Next.js Public Env"),
    (r'REACT_APP_[A-Z_]+["\s]*=["\s]*["\']([A-Za-z0-9_\-\.:/]{10,})["\']',                 "React Env Var"),
    (r'(?i)firebase[A-Za-z]*\s*[=:"\']{1,3}\s*["\']([A-Za-z0-9_\-]{20,})["\']',            "Firebase Config"),
    (r'(?i)github[_-]?token\s*[=:"\']{1,3}([A-Za-z0-9_\-]{20,})',                          "GitHub Token"),
    (r'ghp_[A-Za-z0-9]{36}',                                                                 "GitHub PAT"),
    (r'(?i)twilio[_-]?(?:sid|token|auth)\s*[=:"\']{1,3}([A-Za-z0-9_\-]{20,})',             "Twilio Key"),
    (r'(?i)sendgrid[_-]?(?:key|api)\s*[=:"\']{1,3}([A-Za-z0-9_\-\.]{20,})',               "SendGrid Key"),
    (r'(?i)mailchimp[_-]?(?:key|api)\s*[=:"\']{1,3}([A-Za-z0-9_\-]{20,})',                 "Mailchimp Key"),
    (r'(?i)mapbox[_-]?(?:key|token|pk)\s*[=:"\']{1,3}([A-Za-z0-9_\-\.]{20,})',             "Mapbox Token"),
    (r'pk\.[a-zA-Z0-9]{16}\.[a-zA-Z0-9]{16}',                                               "Stripe Public Key"),
]

# Known false positive patterns — values matching these are NOT real secrets
_FP_VALUE_PATTERNS = [
    r'^!0',                                   # JavaScript minified false
    r'^!1',                                   # JavaScript minified true
    r'^\d+$',                                 # Pure integers
    r'^null$|^undefined$|^true$|^false$',     # JS literals
    r'^\{\{',                                 # Template placeholder {{var}}
    r'^<',                                    # HTML tag
    r'^\[object',                             # JS object string
    r':\s*!0[,}]',                            # JS object property pattern
    r'content-type|text/html|application/',   # MIME types
    r'^[a-z]{1,3}$',                          # 1-3 char JS minified vars
]

# Known false positive context signals
_FP_CONTEXT_PATTERNS = [
    r'\.type\s*[=!]{2}',         # e.type === "password" (DOM attribute check)
    r'type\s*[=!]{2,3}\s*["\']password', # type === "password"
    r'password\s*:\s*!0',        # password:!0 in JS object
    r'input\[type=["\']?password', # CSS selector
    r'autocomplete\s*=\s*["\']?(new-)?password', # HTML autocomplete attr
]

WORDLIST = [
    ".env", ".env.local", ".env.development", ".env.production", ".env.backup", ".env.old",
    "config.json", "config.yml", "config.yaml", "config.php", "config.ini",
    "settings.py", "settings.json", "settings.php", "configuration.php",
    "credentials.json", "credentials.yml", "secrets.json", "secrets.yml", "secrets.env",
    "app.config", "web.config", "appsettings.json",
    "admin", "admin/login", "administrator", "panel", "dashboard", "cms",
    "wp-admin", "wp-login.php", "wp-config.php",
    "login", "signin", "auth", "oauth", "oauth/token", "token", "refresh",
    "backup", "backup.sql", "backup.zip", "backup.tar.gz", "db.sql", "dump.sql",
    "database.sql", "db_backup.sql", "site.zip", "www.zip",
    "api", "api/v1", "api/v2", "v1", "v2", "v3",
    "graphql", "swagger", "api-docs", "openapi.json", "swagger.json", "swagger.yaml",
    "api/swagger", "api/docs",
    ".git", ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG",
    ".svn", ".svn/entries", ".hg",
    "phpinfo.php", "info.php", "test.php", "debug", "debug.php",
    "server-status", "server-info",
    "actuator", "actuator/health", "actuator/env", "actuator/mappings", "actuator/beans",
    "package.json", "package-lock.json", "yarn.lock", "Gemfile",
    "requirements.txt", "composer.json", "composer.lock",
    "logs", "log", "error.log", "access.log", "debug.log", "app.log",
    "db", "database", "phpmyadmin", "adminer.php", "adminer",
    "robots.txt", "sitemap.xml", ".htaccess",
    "metrics", "health", "status", "healthz", "readyz",
    "CHANGELOG.md", "README.md", ".DS_Store",
    "api/users", "api/admin", "api/config", "api/keys", "api/tokens",
    "v1/users", "v1/admin", "v2/users",
    "console", "management", "manager", "control",
    "upload", "uploads", "files", "static/uploads",
    "cgi-bin", "cgi-bin/printenv",
    "trace", "TRACE",
]

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SentinelCore/1.0; Security-Audit)"}


def _noop(*_): pass


def _mask(value: str) -> str:
    if len(value) <= 8:
        return value[:2] + "***"
    return value[:6] + "***" + value[-4:]


def _body_hash(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char. Real credentials typically score > 3.5."""
    if not s or len(s) < 4:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values())


def _is_false_positive(value: str, context: str) -> bool:
    """Return True if the matched value is almost certainly NOT a real secret."""
    # Entropy gate: very low-entropy strings are code/boilerplate, not credentials
    # Exception: short exact-format keys (JWT, PEM) skip entropy check
    if len(value) < 32:
        entropy = _shannon_entropy(value)
        if entropy < 2.8:
            return True

    # Value-level false positive patterns
    for pat in _FP_VALUE_PATTERNS:
        if re.search(pat, value, re.I):
            return True

    # Context-level false positive signals
    for pat in _FP_CONTEXT_PATTERNS:
        if re.search(pat, context, re.I):
            return True

    # Values that look like JS property chains (many colons/commas in short space)
    if len(value) < 50 and value.count(':') + value.count(',') > 3:
        return True

    return False


def _extract_secrets(body: str) -> list:
    found = []
    seen: set = set()
    for pattern, label in SECRET_PATTERNS:
        for match in re.finditer(pattern, body):
            groups = match.groups()
            value = groups[-1] if groups else match.group(0)
            if not value or len(value) < 6:
                continue
            context = body[max(0, match.start()-60):match.end()+60].replace("\n", " ").strip()
            if _is_false_positive(value, context):
                continue
            key = (label, value[:20])
            if key in seen:
                continue
            seen.add(key)
            found.append({
                "type":    label,
                "masked":  _mask(value),
                "raw":     value,
                "context": context,
                "entropy": round(_shannon_entropy(value), 2),
                "source":  "page",
            })
    return found


def _get_baseline(url_base: str, log: callable) -> tuple:
    try:
        r = requests.get(
            f"{url_base.rstrip('/')}/THIS_PATH_DOES_NOT_EXIST_sentinel_xz9q2",
            timeout=5, allow_redirects=True, headers=HEADERS
        )
        log(f"[*] Baseline soft-404: {len(r.content)} bytes (hash {_body_hash(r.content)[:8]}...)")
        return len(r.content), _body_hash(r.content)
    except Exception:
        return -1, ""


def _is_soft_404(r: requests.Response, baseline_size: int, baseline_hash: str) -> bool:
    if baseline_hash and _body_hash(r.content) == baseline_hash:
        return True
    if baseline_size > 0 and len(r.content) == baseline_size:
        return True
    return False


def _detect_cors_issues(response: requests.Response, log: callable) -> list:
    """Detect CORS misconfigurations from response headers."""
    issues = []
    acao = response.headers.get("Access-Control-Allow-Origin", "")
    acac = response.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*":
        issues.append({
            "type": "CORS Wildcard",
            "severity": "Medio",
            "detail": "Access-Control-Allow-Origin: * permite solicitudes desde cualquier origen.",
        })
        log("[!] CORS: Wildcard origin detectado (Access-Control-Allow-Origin: *)")

    if acao not in ("", "*") and acac.lower() == "true":
        issues.append({
            "type": "CORS + Credentials",
            "severity": "Alto",
            "detail": f"CORS con credenciales habilitado para origen: {acao}",
        })
        log(f"[!] CORS crítico: Allow-Credentials=true para origen '{acao}'")

    return issues


def _analyze_cookies(response: requests.Response, log: callable) -> list:
    """Analyze Set-Cookie headers for missing security flags."""
    issues = []
    for header_val in response.headers.getlist("Set-Cookie") if hasattr(response.headers, 'getlist') else [response.headers.get("Set-Cookie", "")]:
        if not header_val:
            continue
        cookie_name = header_val.split("=")[0].strip()
        flags = header_val.lower()
        missing = []
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if "secure" not in flags:
            missing.append("Secure")
        if "samesite" not in flags:
            missing.append("SameSite")
        if missing:
            issues.append({
                "cookie": cookie_name,
                "missing_flags": missing,
                "severity": "Alto" if "HttpOnly" in missing else "Medio",
            })
            log(f"[!] Cookie '{cookie_name}' sin flags: {', '.join(missing)}")
    return issues


def _check_graphql(url_base: str, log: callable) -> dict:
    """Try GraphQL introspection — if enabled, the schema is exposed."""
    endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
    introspection_query = '{"query": "{ __schema { queryType { name } } }"}'
    headers = {**HEADERS, "Content-Type": "application/json"}

    for ep in endpoints:
        url = f"{url_base.rstrip('/')}{ep}"
        try:
            r = requests.post(url, data=introspection_query, headers=headers, timeout=4)
            if r.status_code == 200 and "__schema" in r.text:
                log(f"[!] GraphQL introspection habilitada en {ep} — esquema expuesto")
                return {"endpoint": ep, "exposed": True, "severity": "Alto"}
            elif r.status_code in (200, 400) and "graphql" in r.text.lower():
                log(f"[*] GraphQL detectado en {ep} — introspección deshabilitada")
                return {"endpoint": ep, "exposed": False, "severity": "Info"}
        except Exception:
            continue
    return {}


def _extract_robots_paths(robots_text: str) -> list:
    """Parse robots.txt and extract interesting Disallow paths."""
    interesting = []
    for line in robots_text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line[9:].strip().split("#")[0].strip()
            if path and path not in ("/", ""):
                interesting.append(path)
    return interesting


def _detect_technology(html: str, headers: dict) -> list:
    """Fingerprint technologies from HTML patterns and headers."""
    techs = []
    signals = {
        "Next.js":       r'__NEXT_DATA__|/_next/static/',
        "React":         r'react(?:\.production|\.development|Dom)',
        "Vue.js":        r'__vue_app__|v-cloak|data-v-',
        "Angular":       r'ng-version=|angular\.js|<app-root',
        "WordPress":     r'/wp-content/|wp-includes',
        "Laravel":       r'laravel_session|X-Powered-By.*Laravel',
        "Django":        r'csrfmiddlewaretoken|Django',
        "Rails":         r'_rails_|X-Powered-By.*Phusion|rails\.js',
        "Express":       r'X-Powered-By.*Express',
        "Nuxt":          r'__NUXT_DATA__|/_nuxt/',
        "Gatsby":        r'gatsby-chunk-|window\.___GATSBY',
        "Vite":          r'/@vite/|vite-plugin',
    }
    content = html + " " + str(headers)
    for tech, pattern in signals.items():
        if re.search(pattern, content, re.I):
            techs.append(tech)
    return techs


def _check_source_maps(js_urls: list, log: callable) -> list:
    """Check if .js.map source map files are publicly accessible."""
    exposed = []
    checked = set()
    for url in js_urls[:15]:
        map_url = url.split("?")[0] + ".map"
        if map_url in checked:
            continue
        checked.add(map_url)
        try:
            r = requests.get(map_url, timeout=4, headers=HEADERS)
            if r.status_code == 200 and ('"sources"' in r.text or '"mappings"' in r.text):
                log(f"[!] Source map expuesto: {map_url.split('/')[-1]}")
                exposed.append({"url": map_url, "size_bytes": len(r.content)})
        except Exception:
            continue
    if exposed:
        log(f"[!] {len(exposed)} source map(s) expuesto(s) — el código fuente original es accesible")
    return exposed


def _collect_js_urls(html: str, base_url: str, log: callable) -> list:
    urls: set = set()

    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html, re.I):
        src = m.group(1)
        full = urljoin(base_url, src) if not src.startswith("http") else src
        if urlparse(full).netloc == urlparse(base_url).netloc:
            urls.add(full)

    next_data_match = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', html, re.S)
    if next_data_match:
        log("[*] Next.js detectado — escaneando __NEXT_DATA__ y chunks estáticos")
        try:
            nd = json.loads(next_data_match.group(1))
            build_id = nd.get("buildId", "")
            if build_id:
                manifest_url = f"{base_url.rstrip('/')}/_next/static/{build_id}/_buildManifest.js"
                try:
                    mr = requests.get(manifest_url, timeout=4, headers=HEADERS)
                    if mr.status_code == 200:
                        for chunk in re.findall(r'"([^"]+\.js)"', mr.text):
                            urls.add(urljoin(base_url, f"/_next/static/{chunk}"))
                except Exception:
                    pass
                for chunk_path in [
                    "/_next/static/chunks/main.js",
                    "/_next/static/chunks/webpack.js",
                    f"/_next/static/{build_id}/pages/_app.js",
                    f"/_next/static/{build_id}/pages/index.js",
                ]:
                    urls.add(urljoin(base_url, chunk_path))
        except Exception:
            pass

    for manifest_path in ["/asset-manifest.json", "/_next/static/chunks/"]:
        try:
            mr = requests.get(urljoin(base_url, manifest_path), timeout=3, headers=HEADERS)
            if mr.status_code == 200 and "application/json" in mr.headers.get("Content-Type", ""):
                for js_path in re.findall(r'"([^"]+\.js)"', mr.text):
                    urls.add(urljoin(base_url, js_path))
        except Exception:
            pass

    result = list(urls)
    log(f"[*] {len(result)} bundle(s) JS encontrado(s)")
    return result


def _scan_js_bundles(js_urls: list, log: callable) -> list:
    findings = []
    for i, url in enumerate(js_urls[:20]):
        short = url.split("/")[-1][:50]
        try:
            r = requests.get(url, timeout=5, headers=HEADERS)
            if r.status_code != 200:
                log(f"  [{i+1}/{len(js_urls)}] ✗ {short} — HTTP {r.status_code}")
                continue
            size_kb = len(r.content) // 1024
            secrets = _extract_secrets(r.text[:150_000])
            if secrets:
                log(f"  [{i+1}/{len(js_urls)}] 🚨 {short} ({size_kb}KB) — {len(secrets)} SECRETO(S)")
            else:
                log(f"  [{i+1}/{len(js_urls)}] ✓ {short} ({size_kb}KB) — limpio")
            for s in secrets:
                s["source"] = "js_bundle"
                s["js_url"] = url
                findings.append(s)
        except Exception as ex:
            log(f"  [{i+1}/{len(js_urls)}] ✗ {short} — error: {ex}")
    return findings


def _scan_inline_scripts(html: str, log: callable) -> list:
    findings = []
    blocks = re.findall(r'<script(?:[^>]*)>(.*?)</script>', html, re.S | re.I)
    log(f"[*] {len(blocks)} bloque(s) de script inline encontrado(s)")
    for block in blocks:
        secrets = _extract_secrets(block[:50_000])
        for s in secrets:
            s["source"] = "inline_script"
            s["js_url"] = "(inline)"
            findings.append(s)
    if findings:
        log(f"[!] {len(findings)} secreto(s) en scripts inline")
    return findings


def run_web_enum(target, log_fn=None):
    log = log_fn or _noop
    url_base = target if target.startswith("http") else f"https://{target}"
    results = []
    total_secrets = 0
    js_secrets = []

    log(f"[*] Objetivo: {url_base}")
    log("[*] Iniciando fingerprinting del servidor...")

    try:
        r_home = requests.get(url_base, timeout=8, headers=HEADERS)
        server     = r_home.headers.get("Server", "Oculto")
        powered_by = r_home.headers.get("X-Powered-By", "Desconocida")
        log(f"[+] Servidor: {server} | Tecnología: {powered_by}")

        # ── Technology fingerprinting ────────────────────────────────────────
        detected_techs = _detect_technology(r_home.text, dict(r_home.headers))
        if detected_techs:
            log(f"[+] Tecnologías detectadas: {', '.join(detected_techs)}")

        # ── Security headers ─────────────────────────────────────────────────
        security_header_names = [
            "X-Frame-Options", "Content-Security-Policy",
            "Strict-Transport-Security", "X-Content-Type-Options",
            "Referrer-Policy", "Permissions-Policy",
        ]
        missing_headers = [h for h in security_header_names if not r_home.headers.get(h)]
        if missing_headers:
            log(f"[!] Cabeceras ausentes: {', '.join(missing_headers)}")

        # ── CORS analysis ────────────────────────────────────────────────────
        log("[*] Analizando configuración CORS...")
        cors_issues = _detect_cors_issues(r_home, log)

        # ── Cookie security ──────────────────────────────────────────────────
        log("[*] Analizando flags de seguridad en cookies...")
        cookie_issues = _analyze_cookies(r_home, log)

        # ── GraphQL introspection ────────────────────────────────────────────
        log("[*] Verificando GraphQL...")
        graphql_result = _check_graphql(url_base, log)

        # ── Soft-404 baseline ────────────────────────────────────────────────
        log("[*] Detectando respuesta soft-404 (SPA catch-all)...")
        baseline_size, baseline_hash = _get_baseline(url_base, log)

        # ── JS bundle scanning ───────────────────────────────────────────────
        log("\n[*] === FASE 1: Escaneo de Bundles JavaScript ===")
        js_urls = _collect_js_urls(r_home.text, url_base, log)

        inline_secrets = _scan_inline_scripts(r_home.text, log)
        for s in inline_secrets:
            js_secrets.append(s)
            total_secrets += 1

        if js_urls:
            log(f"[*] Descargando y analizando {min(len(js_urls), 20)} bundles...")
            bundle_secrets = _scan_js_bundles(js_urls, log)
            js_secrets.extend(bundle_secrets)
            total_secrets += len(bundle_secrets)

            # ── Source map detection ─────────────────────────────────────────
            log("[*] Verificando source maps expuestos...")
            exposed_maps = _check_source_maps(js_urls, log)
        else:
            log("[!] No se encontraron bundles JS externos")
            exposed_maps = []

        # ── Robots.txt parsing ───────────────────────────────────────────────
        extra_paths_from_robots = []
        try:
            r_robots = requests.get(f"{url_base.rstrip('/')}/robots.txt", timeout=4, headers=HEADERS)
            if r_robots.status_code == 200 and not _is_soft_404(r_robots, baseline_size, baseline_hash):
                robot_paths = _extract_robots_paths(r_robots.text)
                if robot_paths:
                    log(f"[+] robots.txt: {len(robot_paths)} ruta(s) privada(s) encontradas → auditando")
                    extra_paths_from_robots = robot_paths[:20]
        except Exception:
            pass

        # ── Directory / file fuzzing ─────────────────────────────────────────
        all_paths = list(WORDLIST) + [p.lstrip("/") for p in extra_paths_from_robots]
        log(f"\n[*] === FASE 2: Fuzzing de Directorios ({len(all_paths)} rutas) ===")
        for path in all_paths:
            full_url = f"{url_base.rstrip('/')}/{path.lstrip('/')}"
            try:
                r = requests.get(full_url, timeout=4, allow_redirects=False, headers=HEADERS)

                if r.status_code == 200:
                    if _is_soft_404(r, baseline_size, baseline_hash):
                        continue
                    status = "✅ REAL"
                    log(f"  [+] /{path} — 200 OK ({len(r.content)} bytes, {r.headers.get('Content-Type','').split(';')[0]})")
                elif r.status_code in [301, 302]:
                    status = "🔵 REDIRECCIÓN"
                    log(f"  [~] /{path} — {r.status_code} → {r.headers.get('Location','?')}")
                elif r.status_code == 403:
                    status = "🔴 PROHIBIDO"
                    log(f"  [!] /{path} — 403 PROHIBIDO")
                else:
                    continue

                entry = {
                    "path":         f"/{path}",
                    "status":       status,
                    "code":         r.status_code,
                    "size_bytes":   len(r.content),
                    "content_type": r.headers.get("Content-Type", "").split(";")[0].strip(),
                    "secrets":      [],
                    "snippet":      "",
                }

                if r.status_code == 200:
                    body = r.text[:10_000]
                    entry["secrets"] = _extract_secrets(body)
                    if entry["secrets"]:
                        log(f"  🚨 /{path} — {len(entry['secrets'])} secreto(s) detectado(s)!")
                        total_secrets += len(entry["secrets"])
                    for line in body.splitlines():
                        stripped = line.strip()
                        if stripped and len(stripped) > 5:
                            entry["snippet"] = stripped[:200]
                            break

                results.append(entry)
            except Exception:
                continue

        log(f"\n[+] === ANÁLISIS COMPLETADO ===")
        log(f"[+] Rutas reales: {len(results)} | Secretos totales: {total_secrets}")
        if cors_issues:
            log(f"[!] Problemas CORS: {len(cors_issues)}")
        if cookie_issues:
            log(f"[!] Cookies inseguras: {len(cookie_issues)}")
        if exposed_maps:
            log(f"[!] Source maps expuestos: {len(exposed_maps)}")
        if total_secrets == 0:
            log("[*] No se detectaron secretos expuestos")

        return {
            "target":                   url_base,
            "server":                   server,
            "tech":                     powered_by,
            "detected_techs":           detected_techs,
            "found_paths":              results,
            "js_bundles_scanned":       len(js_urls),
            "js_secrets":               js_secrets,
            "total_secrets_found":      total_secrets,
            "missing_security_headers": missing_headers,
            "cors_issues":              cors_issues,
            "cookie_issues":            cookie_issues,
            "graphql":                  graphql_result,
            "exposed_source_maps":      exposed_maps,
            "robots_private_paths":     extra_paths_from_robots,
            "soft404_baseline_size":    baseline_size,
            "timestamp":                datetime.now().strftime("%H:%M:%S"),
        }
    except Exception as e:
        log(f"[!] Error crítico: {e}")
        return {"error": str(e)}
