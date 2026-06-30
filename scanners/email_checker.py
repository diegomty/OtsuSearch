"""
email_checker.py — Sentinel-Core AI
Análisis de seguridad de email: SPF, DMARC, DKIM, MX, SMTP banner.
"""
import re
import socket

try:
    import dns.resolver as _dns_resolver
    _DNS_OK = True
except ImportError:
    _DNS_OK = False

# ── Selectores DKIM comunes a probar ─────────────────────────────────────────
_DKIM_SELECTORS = [
    'default', 'google', 'mail', 'email', 'k1', 'dkim',
    'selector1', 'selector2', 's1', 's2', 'mandrill',
    'smtp', 'protonmail', 'zoho', 'sendgrid', 'mailchimp',
]

_SPF_ALL_MAP = {
    '+all': ('CRÍTICO', 'Permite que CUALQUIER servidor envíe como este dominio — equivale a no tener SPF'),
    '?all': ('ALTO',    'Política neutral: sin efecto protector real'),
    '~all': ('MEDIO',   'SoftFail: correos no autorizados se marcan pero se entregan'),
    '-all': ('OK',      'HardFail: correos no autorizados se rechazan (correcto)'),
}


# ── Utilidad DNS ──────────────────────────────────────────────────────────────

def _dns_txt(name: str) -> list:
    """Returns list of TXT record strings for a given name."""
    if not _DNS_OK:
        return []
    try:
        answers = _dns_resolver.resolve(name, 'TXT', lifetime=8)
        return [b''.join(r.strings).decode('utf-8', errors='ignore') for r in answers]
    except Exception:
        return []


def _dns_mx(domain: str) -> list:
    if not _DNS_OK:
        return []
    try:
        answers = _dns_resolver.resolve(domain, 'MX', lifetime=8)
        return sorted(
            [{'host': str(r.exchange).rstrip('.'), 'priority': r.preference} for r in answers],
            key=lambda x: x['priority']
        )
    except Exception:
        return []


# ── SPF ───────────────────────────────────────────────────────────────────────

def _check_spf(domain: str, log) -> dict:
    log(f"[*] Consultando SPF ({domain})...")
    txts = _dns_txt(domain)
    record = next((t for t in txts if t.startswith('v=spf1')), None)

    if not record:
        log("  [-] SPF: No encontrado")
        return {
            'present':     False,
            'record':      '',
            'severity':    'ALTO',
            'policy':      'AUSENTE',
            'description': 'Sin registro SPF — cualquier servidor puede falsificar el remitente',
        }

    log(f"  [+] SPF: {record[:100]}")

    severity    = 'BAJO'
    policy      = 'desconocida'
    description = ''
    for mech, (sev, desc) in _SPF_ALL_MAP.items():
        if mech in record:
            severity    = sev
            policy      = mech
            description = desc
            break

    includes    = re.findall(r'include:(\S+)', record)
    redirects   = re.findall(r'redirect=(\S+)', record)
    mechanisms  = re.findall(r'(?:ip4|ip6|a|mx|ptr|exists)(?::[^\s]+)?', record)

    too_many_lookups = (len(includes) + len(redirects) + len(mechanisms)) > 10

    return {
        'present':           True,
        'record':            record,
        'severity':          severity,
        'policy':            policy,
        'description':       description,
        'includes':          includes,
        'too_many_lookups':  too_many_lookups,
    }


# ── DMARC ─────────────────────────────────────────────────────────────────────

def _check_dmarc(domain: str, log) -> dict:
    log(f"[*] Consultando DMARC (_dmarc.{domain})...")
    txts   = _dns_txt(f'_dmarc.{domain}')
    record = next((t for t in txts if 'v=DMARC1' in t), None)

    if not record:
        log("  [-] DMARC: No encontrado")
        return {
            'present':      False,
            'record':       '',
            'severity':     'CRÍTICO',
            'policy':       'AUSENTE',
            'policy_desc':  'Sin DMARC — dominio completamente vulnerable a email spoofing/phishing',
        }

    log(f"  [+] DMARC: {record[:100]}")

    p_match = re.search(r'\bp=(\w+)', record)
    policy  = p_match.group(1).lower() if p_match else 'none'

    sp_match = re.search(r'\bsp=(\w+)', record)
    sp       = sp_match.group(1).lower() if sp_match else policy

    rua_match = re.search(r'rua=([^;]+)', record)
    rua       = rua_match.group(1).strip() if rua_match else ''

    pct_match = re.search(r'pct=(\d+)', record)
    pct       = int(pct_match.group(1)) if pct_match else 100

    _policy_map = {
        'none':       ('ALTO',   'Solo monitoreo — los emails falsos se entregan normalmente'),
        'quarantine': ('MEDIO',  'Emails sospechosos van a cuarentena/spam'),
        'reject':     ('OK',     'Emails no autorizados son rechazados (política óptima)'),
    }
    severity, policy_desc = _policy_map.get(policy, ('MEDIO', 'Política desconocida'))

    return {
        'present':      True,
        'record':       record,
        'policy':       policy,
        'sp':           sp,
        'severity':     severity,
        'policy_desc':  policy_desc,
        'rua':          rua,
        'pct':          pct,
        'has_rua':      bool(rua),
    }


# ── DKIM ──────────────────────────────────────────────────────────────────────

def _check_dkim(domain: str, log) -> dict:
    log(f"[*] Probando selectores DKIM ({len(_DKIM_SELECTORS)} selectores)...")
    found = []

    for selector in _DKIM_SELECTORS:
        txts = _dns_txt(f'{selector}._domainkey.{domain}')
        for txt in txts:
            if 'p=' in txt or 'k=' in txt:
                log(f"  [+] DKIM selector '{selector}' encontrado")
                p_match  = re.search(r'p=([A-Za-z0-9+/=]+)', txt)
                key_size = len(p_match.group(1)) * 6 // 8 * 8 if p_match else 0
                found.append({
                    'selector':  selector,
                    'record':    (txt[:120] + '...') if len(txt) > 120 else txt,
                    'key_bits':  key_size,
                    'weak_key':  (key_size > 0 and key_size < 2048),
                })
                break

    if not found:
        log("  [-] DKIM: No detectado en selectores comunes")

    return {
        'present':   bool(found),
        'selectors': found,
        'severity':  'OK' if found else 'MEDIO',
    }


# ── MX ───────────────────────────────────────────────────────────────────────

def _check_mx(domain: str, log) -> dict:
    log(f"[*] Consultando registros MX ({domain})...")
    records = _dns_mx(domain)

    for r in records:
        log(f"  [+] MX {r['priority']}: {r['host']}")

    if not records:
        log("  [-] MX: No encontrado")

    return {'present': bool(records), 'records': records}


# ── SMTP banner ───────────────────────────────────────────────────────────────

def _grab_smtp_banner(mx_host: str, log) -> dict:
    log(f"[*] Banner SMTP de {mx_host}:25...")
    try:
        with socket.create_connection((mx_host, 25), timeout=6) as sock:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            log(f"  [+] Banner: {banner[:80]}")
            return {
                'banner':          banner,
                'version_exposed': bool(re.search(r'\d+\.\d+[\.\d]*', banner)),
            }
    except Exception as e:
        log(f"  [-] SMTP no accesible: {e}")
        return {'banner': '', 'version_exposed': False}


# ── Generación de hallazgos ───────────────────────────────────────────────────

def _build_findings(domain: str, spf: dict, dmarc: dict, dkim: dict, mx: dict, smtp: dict) -> list:
    findings = []

    # ── SPF ──
    if not spf.get('present'):
        findings.append({
            'id': 'EMAIL-001', 'severity': 'ALTO',
            'title': 'Registro SPF ausente',
            'detail': f'El dominio {domain} no tiene SPF. Cualquier servidor puede enviar emails en su nombre.',
            'remediation': 'Crear TXT: v=spf1 include:<tu-proveedor-smtp> -all',
            'compliance': 'RFC 7208 / DMARC Best Practices'
        })
    elif '+all' in spf.get('record', ''):
        findings.append({
            'id': 'EMAIL-002', 'severity': 'CRÍTICO',
            'title': 'SPF con política +all (permite todo)',
            'detail': '"+all" autoriza cualquier servidor — la protección SPF queda completamente anulada.',
            'remediation': 'Reemplazar "+all" por "-all" para rechazar servidores no autorizados.',
            'compliance': 'RFC 7208 §5.6'
        })
    elif '~all' in spf.get('record', ''):
        findings.append({
            'id': 'EMAIL-003', 'severity': 'MEDIO',
            'title': 'SPF con política ~all (SoftFail)',
            'detail': 'SoftFail entrega correos no autorizados marcados como sospechosos, sin rechazarlos.',
            'remediation': 'Migrar de ~all a -all para enforcer rechazo completo.',
            'compliance': 'RFC 7208 / Email Security Best Practices'
        })

    if spf.get('too_many_lookups'):
        findings.append({
            'id': 'EMAIL-004', 'severity': 'MEDIO',
            'title': 'SPF supera 10 DNS lookups (RFC 7208 límite)',
            'detail': 'Demasiados mecanismos include/redirect causan fallo SPF en algunos receptores (PermError).',
            'remediation': 'Usar SPF flattening para reducir lookups o un servicio como dmarcian.',
            'compliance': 'RFC 7208 §4.6.4'
        })

    # ── DMARC ──
    if not dmarc.get('present'):
        findings.append({
            'id': 'EMAIL-010', 'severity': 'CRÍTICO',
            'title': 'Registro DMARC ausente',
            'detail': f'Sin DMARC, el dominio {domain} es directamente explotable para campañas de phishing/spoofing.',
            'remediation': f'Crear TXT en _dmarc.{domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}',
            'compliance': 'RFC 7489 / CISA Email Security Guidance'
        })
    elif dmarc.get('policy') == 'none':
        findings.append({
            'id': 'EMAIL-011', 'severity': 'ALTO',
            'title': 'DMARC en modo "none" (sin protección activa)',
            'detail': 'p=none solo genera reportes. Los emails falsos se entregan normalmente a los destinatarios.',
            'remediation': 'Escalar a p=quarantine (transición) y luego p=reject (objetivo final).',
            'compliance': 'RFC 7489 §6.3'
        })

    if dmarc.get('present') and not dmarc.get('has_rua'):
        findings.append({
            'id': 'EMAIL-012', 'severity': 'BAJO',
            'title': 'DMARC sin dirección de reporte (rua)',
            'detail': 'Sin rua=, no se reciben reportes de abuso. Imposible detectar intentos de spoofing.',
            'remediation': 'Agregar rua=mailto:dmarc@tudominio.com al registro DMARC.',
            'compliance': 'RFC 7489 §7.1'
        })

    # ── DKIM ──
    if not dkim.get('present'):
        findings.append({
            'id': 'EMAIL-020', 'severity': 'MEDIO',
            'title': 'DKIM no detectado en selectores comunes',
            'detail': 'Sin DKIM, no es posible verificar que el email proviene del servidor legítimo. Falla validación DMARC.',
            'remediation': 'Generar par de claves DKIM en el MTA y publicar la clave pública en DNS.',
            'compliance': 'RFC 6376 / DMARC compliance'
        })

    for sel in dkim.get('selectors', []):
        if sel.get('weak_key') and sel.get('key_bits', 0) > 0:
            findings.append({
                'id': 'EMAIL-021', 'severity': 'MEDIO',
                'title': f'Clave DKIM débil (selector: {sel["selector"]}, ~{sel["key_bits"]} bits)',
                'detail': f'Clave RSA < 2048 bits. Vulnerable a factorización en hardware moderno.',
                'remediation': 'Regenerar clave DKIM con RSA 2048 o superior (recomendado: 4096 bits).',
                'compliance': 'NIST SP 800-57 / RFC 6376 §3.3'
            })

    # ── SMTP ──
    if smtp.get('version_exposed'):
        findings.append({
            'id': 'EMAIL-030', 'severity': 'BAJO',
            'title': 'Versión de servidor SMTP expuesta en banner',
            'detail': f'Banner: "{smtp.get("banner", "")[:100]}" — revela software y versión.',
            'remediation': 'Ocultar versión: en Postfix, configurar smtpd_banner = $myhostname ESMTP',
            'compliance': 'CIS Benchmark / Security by Obscurity'
        })

    return findings


# ── Entry point ───────────────────────────────────────────────────────────────

def run_email_security_check(domain: str, log_fn=None) -> dict:
    def log(msg):
        if log_fn:
            log_fn(msg)

    if not _DNS_OK:
        log("[!] dnspython no instalado. Ejecuta: pip install dnspython")
        return {'error': 'dnspython no instalado', 'findings': []}

    domain = re.sub(r'^https?://', '', domain).split('/')[0].strip()
    log(f"[*] Sentinel-Email — Análisis para: {domain}")

    spf   = _check_spf(domain, log)
    dmarc = _check_dmarc(domain, log)
    dkim  = _check_dkim(domain, log)
    mx    = _check_mx(domain, log)

    smtp = {'banner': '', 'version_exposed': False}
    if mx.get('records'):
        smtp = _grab_smtp_banner(mx['records'][0]['host'], log)

    findings = _build_findings(domain, spf, dmarc, dkim, mx, smtp)

    crits  = sum(1 for f in findings if f['severity'] == 'CRÍTICO')
    highs  = sum(1 for f in findings if f['severity'] == 'ALTO')
    mediums = sum(1 for f in findings if f['severity'] == 'MEDIO')

    log(f"[+] Análisis completado — {len(findings)} hallazgo(s): "
        f"{crits} crítico(s), {highs} alto(s), {mediums} medio(s)")

    return {
        'tool':     'Sentinel-Email',
        'domain':   domain,
        'spf':      spf,
        'dmarc':    dmarc,
        'dkim':     dkim,
        'mx':       mx,
        'smtp':     smtp,
        'findings': findings,
        'summary':  {'criticos': crits, 'altos': highs, 'medios': mediums},
    }
