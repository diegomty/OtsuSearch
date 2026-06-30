"""
ssl_analyzer.py — Sentinel-Core AI
Análisis completo de SSL/TLS: certificado, protocolos, cipher suites, HSTS, vulnerabilidades NSE.
"""
import ssl
import socket
import subprocess
import datetime
import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Cipher suites considerados débiles ──────────────────────────────────────
_WEAK_CIPHERS = ['RC4', 'NULL', '3DES', 'DES', 'EXPORT', 'anon', 'MD5']

# ── Hallazgos: SSLv3/TLS mapeo a severidad ──────────────────────────────────
_PROTO_SEVERITY = {
    'SSLv2':  ('CRÍTICO', 'SSLv2 tiene vulnerabilidades críticas conocidas. Deprecado en 2011.'),
    'SSLv3':  ('CRÍTICO', 'SSLv3 es vulnerable a POODLE (CVE-2014-3566). Deprecado en RFC 7568.'),
    'TLS 1.0': ('ALTO',   'TLS 1.0 es vulnerable a BEAST. Deprecado por PCI-DSS desde 2018 (RFC 8996).'),
    'TLS 1.1': ('MEDIO',  'TLS 1.1 fue deprecado por IETF en RFC 8996 (2021).'),
}


# ── Certificado ──────────────────────────────────────────────────────────────

def _get_cert_info(host: str, port: int, log) -> dict:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert    = ssock.getpeercert()
                cipher  = ssock.cipher()
                version = ssock.version()

                not_after  = cert.get('notAfter', '')
                expiry_dt  = None
                days_left  = None
                if not_after:
                    try:
                        expiry_dt = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expiry_dt - datetime.datetime.utcnow()).days
                    except Exception:
                        pass

                sans = [v for t, v in cert.get('subjectAltName', []) if t == 'DNS']

                subject = {k: v for rdn in cert.get('subject', []) for k, v in rdn}
                issuer  = {k: v for rdn in cert.get('issuer', [])  for k, v in rdn}

                log(f"  [+] CN: {subject.get('commonName', '?')}")
                log(f"  [+] Emisor: {issuer.get('organizationName', '?')}")
                log(f"  [+] Expira: {expiry_dt.strftime('%Y-%m-%d') if expiry_dt else '?'} ({days_left} días)")
                log(f"  [+] Protocolo negociado: {version}  |  Cipher: {cipher[0] if cipher else '?'}")

                return {
                    'ok': True,
                    'subject_cn':          subject.get('commonName', ''),
                    'subject_o':           subject.get('organizationName', ''),
                    'issuer_o':            issuer.get('organizationName', ''),
                    'issuer_cn':           issuer.get('commonName', ''),
                    'not_after':           not_after,
                    'expiry_date':         expiry_dt.strftime('%Y-%m-%d') if expiry_dt else '?',
                    'days_left':           days_left,
                    'sans':                sans,
                    'negotiated_protocol': version,
                    'negotiated_cipher':   cipher[0] if cipher else '',
                    'self_signed':         subject.get('commonName') == issuer.get('commonName'),
                }
    except ssl.SSLError as e:
        log(f"  [!] SSL Error: {e}")
        return {'ok': False, 'error': str(e)}
    except Exception as e:
        log(f"  [!] Error de conexión: {e}")
        return {'ok': False, 'error': str(e)}


# ── Versiones de protocolo vía openssl s_client ──────────────────────────────

def _check_protocols(host: str, port: int, log) -> dict:
    probes = {
        'TLS 1.0': ['-tls1'],
        'TLS 1.1': ['-tls1_1'],
        'TLS 1.2': ['-tls1_2'],
        'TLS 1.3': ['-tls1_3'],
    }
    results = {}
    for name, flags in probes.items():
        try:
            cmd = ['openssl', 's_client'] + flags + ['-connect', f'{host}:{port}', '-brief']
            r = subprocess.run(cmd, input=b'Q\n', capture_output=True, timeout=6)
            out = (r.stdout + r.stderr).decode('utf-8', errors='ignore')
            supported = ('CONNECTION ESTABLISHED' in out or
                         'Certificate chain' in out or
                         'SSL-Session' in out or
                         'CONNECTED' in out)
            results[name] = supported
            status = "HABILITADO" if supported else "deshabilitado"
            sev_tag = f" ⚠" if (supported and name in _PROTO_SEVERITY) else ""
            log(f"  {'[+]' if supported else '[-]'} {name}: {status}{sev_tag}")
        except FileNotFoundError:
            results[name] = None
            log(f"  [?] openssl no encontrado en PATH")
            break
        except subprocess.TimeoutExpired:
            results[name] = None
    return results


# ── HSTS ─────────────────────────────────────────────────────────────────────

def _check_hsts(host: str, log) -> dict:
    for scheme in ('https', 'http'):
        try:
            resp = requests.get(f'{scheme}://{host}', timeout=5, verify=False, allow_redirects=False)
            hsts_val = resp.headers.get('Strict-Transport-Security', '')
            if hsts_val:
                log(f"  [+] HSTS: {hsts_val}")
                max_age = re.search(r'max-age=(\d+)', hsts_val)
                return {
                    'present':             True,
                    'value':               hsts_val,
                    'max_age_seconds':     int(max_age.group(1)) if max_age else 0,
                    'includes_subdomains': 'includeSubDomains' in hsts_val,
                    'preload':             'preload' in hsts_val,
                }
            break
        except Exception:
            continue
    log(f"  [-] HSTS: NO configurado")
    return {'present': False, 'value': ''}


# ── NSE Scripts SSL ───────────────────────────────────────────────────────────

def _run_nmap_ssl(host: str, port: int, log) -> dict:
    try:
        cmd = [
            'nmap', '--script',
            'ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-drown,ssl-cert,ssl-dh-params',
            '-p', str(port), host, '-oN', '-', '--open'
        ]
        r = subprocess.run(cmd, capture_output=True, timeout=90, text=True)
        out = r.stdout

        vulns       = [l.strip() for l in out.split('\n') if 'VULNERABLE' in l.upper()]
        weak_found  = [c for c in _WEAK_CIPHERS if c in out]
        grade       = re.search(r'least strength: ([A-F])', out)

        return {
            'raw':             out[:3000],
            'vulnerabilities': vulns,
            'weak_ciphers':    weak_found,
            'cipher_grade':    grade.group(1) if grade else None,
        }
    except Exception as e:
        return {'raw': '', 'vulnerabilities': [], 'weak_ciphers': [], 'cipher_grade': None, 'error': str(e)}


# ── Generación de hallazgos ───────────────────────────────────────────────────

def _build_findings(cert: dict, protocols: dict, hsts: dict, nmap: dict) -> list:
    findings = []

    # Certificado expirado / próximo a expirar
    if cert.get('ok'):
        days = cert.get('days_left')
        if days is not None:
            if days < 0:
                findings.append({
                    'id': 'SSL-001', 'severity': 'CRÍTICO',
                    'title': 'Certificado SSL/TLS expirado',
                    'detail': f'El certificado expiró hace {abs(days)} días ({cert["expiry_date"]}).',
                    'remediation': 'Renovar el certificado inmediatamente con la CA emisora.',
                    'compliance': 'PCI-DSS 4.2.1 / ISO 27001 A.10.1'
                })
            elif days < 30:
                findings.append({
                    'id': 'SSL-002', 'severity': 'ALTO',
                    'title': f'Certificado expira en {days} días',
                    'detail': f'Expiración: {cert["expiry_date"]}. Riesgo de interrupción del servicio.',
                    'remediation': 'Renovar el certificado antes de la fecha de expiración.',
                    'compliance': 'PCI-DSS 4.2.1'
                })

        if cert.get('self_signed'):
            findings.append({
                'id': 'SSL-003', 'severity': 'ALTO',
                'title': 'Certificado autofirmado (Self-Signed)',
                'detail': 'Los clientes no pueden verificar la autenticidad del servidor sin una CA de confianza.',
                'remediation': 'Reemplazar con certificado emitido por CA pública (Let\'s Encrypt, DigiCert, etc.)',
                'compliance': 'NIST SP 800-52 / PCI-DSS 4.2'
            })

    # Protocolos obsoletos
    for proto, (severity, desc) in _PROTO_SEVERITY.items():
        if protocols.get(proto) is True:
            findings.append({
                'id': f'SSL-{10 + list(_PROTO_SEVERITY).index(proto)}',
                'severity': severity,
                'title': f'{proto} habilitado (protocolo obsoleto)',
                'detail': desc,
                'remediation': f'Deshabilitar {proto} en la configuración del servidor web/balanceador.',
                'compliance': 'PCI-DSS 4.2.1 / NIST SP 800-52r2'
            })

    # HSTS
    if hsts.get('present') is False:
        findings.append({
            'id': 'SSL-020', 'severity': 'MEDIO',
            'title': 'HSTS (HTTP Strict Transport Security) no configurado',
            'detail': 'Sin HSTS, los clientes pueden ser víctimas de ataques de downgrade a HTTP.',
            'remediation': 'Agregar cabecera: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'compliance': 'OWASP A05 / NIST SP 800-52'
        })
    elif hsts.get('present') and hsts.get('max_age_seconds', 0) < 15552000:
        findings.append({
            'id': 'SSL-021', 'severity': 'BAJO',
            'title': 'HSTS max-age insuficiente (< 180 días)',
            'detail': f'max-age={hsts.get("max_age_seconds")}s. Se recomienda mínimo 1 año (31536000s).',
            'remediation': 'Aumentar max-age a 31536000 o superior.',
            'compliance': 'OWASP ASVS V9.1'
        })

    # Cipher grade
    grade = nmap.get('cipher_grade')
    if grade and grade in ('C', 'D', 'E', 'F'):
        findings.append({
            'id': 'SSL-030', 'severity': 'ALTO',
            'title': f'Calidad de cipher suites: Grado {grade}',
            'detail': f'nmap ssl-enum-ciphers califica las cipher suites como grado {grade}.',
            'remediation': 'Revisar y deshabilitar cipher suites obsoletas. Objetivo: Grado A.',
            'compliance': 'PCI-DSS 4.2.1 / NIST SP 800-52'
        })

    # Ciphers débiles
    for cipher in nmap.get('weak_ciphers', []):
        findings.append({
            'id': 'SSL-031', 'severity': 'ALTO',
            'title': f'Cipher suite inseguro detectado: {cipher}',
            'detail': f'{cipher} está considerado criptográficamente débil por NIST y PCI-DSS.',
            'remediation': f'Deshabilitar todas las variantes de {cipher} en la configuración TLS.',
            'compliance': 'PCI-DSS 4.2.1'
        })

    # NSE vulnerabilities
    for vuln_line in nmap.get('vulnerabilities', []):
        findings.append({
            'id': 'SSL-040', 'severity': 'CRÍTICO',
            'title': 'Vulnerabilidad crítica SSL detectada (NSE)',
            'detail': vuln_line,
            'remediation': 'Aplicar parche del fabricante y actualizar OpenSSL a la versión más reciente.',
            'compliance': 'CVE / NVD'
        })

    return findings


# ── Entry point ───────────────────────────────────────────────────────────────

def run_ssl_analysis(host: str, port: int = 443, log_fn=None) -> dict:
    def log(msg):
        if log_fn:
            log_fn(msg)

    # Strip protocol prefix if present
    host = re.sub(r'^https?://', '', host).split('/')[0].strip()

    log(f"[*] Sentinel-SSL — Análisis de {host}:{port}")

    log("[*] Obteniendo información del certificado...")
    cert = _get_cert_info(host, port, log)

    log("[*] Verificando versiones de protocolo TLS...")
    protocols = _check_protocols(host, port, log)

    log("[*] Verificando HSTS...")
    hsts = _check_hsts(host, log)

    log("[*] Ejecutando scripts NSE ssl-*...")
    nmap_ssl = _run_nmap_ssl(host, port, log)

    findings = _build_findings(cert, protocols, hsts, nmap_ssl)

    # Severity summary
    crits  = sum(1 for f in findings if f['severity'] == 'CRÍTICO')
    highs  = sum(1 for f in findings if f['severity'] == 'ALTO')
    mediums = sum(1 for f in findings if f['severity'] == 'MEDIO')

    log(f"[+] Análisis SSL completado — {len(findings)} hallazgo(s): "
        f"{crits} crítico(s), {highs} alto(s), {mediums} medio(s)")

    return {
        'tool':        'Sentinel-SSL',
        'host':        host,
        'port':        port,
        'certificate': cert,
        'protocols':   protocols,
        'hsts':        hsts,
        'nmap_ssl':    nmap_ssl,
        'findings':    findings,
        'summary':     {'criticos': crits, 'altos': highs, 'medios': mediums},
    }
