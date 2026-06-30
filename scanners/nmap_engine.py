import nmap
import json
import os
import re
import time
import subprocess
import urllib.parse
import requests
from datetime import datetime

# ── Input validation ─────────────────────────────────────────────────────────
_VALID_TARGET = re.compile(
    r'^('
    r'(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?'   # IPv4 / CIDR
    r'|(\d{1,3}\.){3}\d{1,3}-\d{1,3}'     # IPv4 range: 192.168.1.1-50
    r'|[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?'  # hostname/domain
    r')$'
)

def _sanitize_target(value: str) -> str:
    """Validate target is a clean IP/CIDR/hostname. Raises ValueError if suspicious."""
    v = value.strip()
    if not v:
        raise ValueError("El objetivo no puede estar vacío.")
    if not _VALID_TARGET.match(v):
        raise ValueError(
            f"Objetivo inválido: '{v}'. Solo se permiten IPs, rangos CIDR o hostnames."
        )
    return v

# ── NSE script chains: port → comma-separated scripts ───────────────────────
NSE_CHAINS = {
    21:    "ftp-anon,ftp-syst,ftp-vsftpd-backdoor,ftp-bounce",
    22:    "ssh-hostkey,ssh-auth-methods,ssh2-enum-algos",
    23:    "telnet-encryption,telnet-ntlm-info",
    25:    "smtp-commands,smtp-enum-users,smtp-open-relay,smtp-ntlm-info",
    53:    "dns-zone-transfer,dns-recursion,dns-cache-snoop",
    79:    "finger,finger-user-enum",
    80:    "http-title,http-methods,http-waf-detect,http-server-header,http-shellshock",
    110:   "pop3-capabilities,pop3-brute",
    111:   "rpcinfo,nfs-showmount",
    139:   "smb-security-mode,smb-enum-shares,smb-enum-users,smb-system-info",
    143:   "imap-capabilities,imap-brute",
    161:   "snmp-info,snmp-brute,snmp-sysdescr",
    443:   "ssl-cert,ssl-enum-ciphers,http-waf-detect,ssl-dh-params",
    445:   "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-security-mode,smb-enum-shares,smb-enum-users",
    1433:  "ms-sql-info,ms-sql-empty-password,ms-sql-config",
    2049:  "nfs-showmount,nfs-ls,nfs-statfs",
    3306:  "mysql-info,mysql-empty-password,mysql-databases,mysql-enum",
    3389:  "rdp-enum-encryption,rdp-vuln-ms12-020",
    5432:  "pgsql-brute",
    5900:  "vnc-info,vnc-brute",
    6379:  "redis-info",
    8080:  "http-title,http-methods,http-waf-detect,http-open-proxy",
    8443:  "ssl-cert,http-methods,http-waf-detect",
    27017: "mongodb-info,mongodb-databases",
}

CRITICAL_PORTS = {21, 23, 445, 3306, 5432, 1433, 3389, 4444, 5900, 6379, 27017, 2049, 161}

_NVD_LAST_CALL = 0
_NVD_MIN_INTERVAL = 6  # NIST NVD free tier: max ~10 req/min


def _noop(*_): pass


def _run_nse_chain(target: str, port: int, log: callable) -> dict:
    """Run port-specific NSE scripts and return script output dict."""
    scripts = NSE_CHAINS.get(port)
    if not scripts:
        return {}
    log(f"  [NSE] Puerto {port} → scripts: {scripts}")
    try:
        nm2 = nmap.PortScanner()
        nm2.scan(hosts=target, ports=str(port), arguments=f"--script={scripts} -sV -T4", timeout=90)
        if target not in nm2.all_hosts():
            return {}
        script_results = {}
        for proto in nm2[target].all_protocols():
            if port in nm2[target][proto]:
                script_results = nm2[target][proto][port].get("script", {})
        if script_results:
            log(f"  [NSE] ✓ {len(script_results)} resultado(s) para puerto {port}")
            ALERT_KEYWORDS = [
                "VULNERABLE", "EternalBlue", "MS17-010", "MS08-067",
                "anonymous", "empty password", "allowed", "EXPOSED",
            ]
            for sname, sout in script_results.items():
                for kw in ALERT_KEYWORDS:
                    if kw.lower() in sout.lower():
                        log(f"  🚨 [NSE] CRÍTICO — {sname}: '{kw}' detectado")
                        break
        return {"port": port, "scripts": script_results}
    except Exception as e:
        log(f"  [NSE] Error en puerto {port}: {e}")
        return {}


def _lookup_cves(product: str, version: str, log: callable) -> list:
    """Query NIST NVD API for CVEs matching product+version. Returns top 5 sorted by priority."""
    global _NVD_LAST_CALL
    if not product or product.strip() in ("", "?", "tcpwrapped"):
        return []

    # Rate-limit NVD calls
    elapsed = time.time() - _NVD_LAST_CALL
    if elapsed < _NVD_MIN_INTERVAL:
        time.sleep(_NVD_MIN_INTERVAL - elapsed)

    query = f"{product} {version}".strip()
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={urllib.parse.quote(query)}&resultsPerPage=5"
    )
    try:
        r = requests.get(url, timeout=12, headers={"User-Agent": "Sentinel-Core/1.0"})
        _NVD_LAST_CALL = time.time()
        if r.status_code != 200:
            log(f"  [CVE] NVD API: HTTP {r.status_code} para '{query}'")
            return []
        data = r.json()
        vulns = []
        for item in data.get("vulnerabilities", [])[:5]:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "Sin descripción",
            )[:300]
            cvss_score = 0.0
            severity = "N/A"
            conf_impact = 1.0
            atk_complexity = 1.0
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                entries = (cve.get("metrics") or {}).get(key, [])
                if entries:
                    cd = entries[0].get("cvssData", {})
                    cvss_score = float(cd.get("baseScore", 0))
                    severity = cd.get("baseSeverity", "N/A")
                    ci_map = {"HIGH": 3.0, "MEDIUM": 2.0, "LOW": 1.0, "NONE": 0.5}
                    ac_map = {"LOW": 1.0, "MEDIUM": 1.5, "HIGH": 2.0}
                    conf_impact    = ci_map.get(str(cd.get("confidentialityImpact", "LOW")), 1.0)
                    atk_complexity = ac_map.get(str(cd.get("attackComplexity", "LOW")), 1.0)
                    break
            # Priority = (CVSS_Base × Confidentiality) / Attack_Complexity
            priority = round((cvss_score * conf_impact) / atk_complexity, 2)
            vulns.append({
                "cve_id":        cve_id,
                "cvss":          cvss_score,
                "severity":      severity,
                "priority":      priority,
                "description":   desc,
                "nvd_url":       f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "exploitdb_url": f"https://www.exploit-db.com/search?q={urllib.parse.quote(cve_id)}",
            })
        vulns.sort(key=lambda x: x["priority"], reverse=True)
        if vulns:
            log(f"  [CVE] {len(vulns)} CVE(s) para '{query}' — top CVSS: {vulns[0]['cvss']}")
        return vulns
    except Exception as e:
        log(f"  [CVE] Error consultando NVD: {e}")
        return []


def _detect_ids_waf(target: str, log: callable) -> dict:
    """Send TCP null/fin/xmas probes to detect IDS, WAF, or stateful firewall."""
    log("[*] === Detección de IDS/WAF/Firewall (probes TCP anómalos) ===")
    probes = [
        ("-sN", "Null"),
        ("-sF", "FIN"),
        ("-sX", "Xmas"),
    ]
    responses = {}
    for flag, name in probes:
        try:
            # Target passed as a separate list element — never split with user input
            cmd = ['nmap', flag, '-p', '80,443,22,445', '--max-retries', '1', '-T2', target]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            out = proc.stdout.lower()
            if "filtered" in out:
                v = "filtered"
            elif "open" in out:
                v = "open"
            elif "closed" in out:
                v = "closed"
            else:
                v = "no-response"
            responses[name] = v
            log(f"  [IDS] Probe TCP {name}: {v}")
        except subprocess.TimeoutExpired:
            responses[name] = "timeout"
            log(f"  [IDS] Probe TCP {name}: timeout")
        except Exception as e:
            responses[name] = "error"
            log(f"  [IDS] Probe TCP {name}: error — {e}")

    values = list(responses.values())
    all_blocked   = all(v in ("filtered", "timeout", "no-response") for v in values)
    inconsistent  = len(set(values)) > 1

    if all_blocked:
        itype = "Firewall Restrictivo"
        evasion = (
            f"nmap -f --mtu 16 -D RND:10 -T2 -sS {target}  "
            f"# Fragmentación + señuelos (decoys)"
        )
        log(f"  [IDS] 🛡️ Firewall restrictivo detectado")
    elif inconsistent:
        itype = "IPS/WAF Dinámico"
        evasion = (
            f"nmap --script=http-waf-detect -f -D RND:5 --data-length 200 {target}"
        )
        log(f"  [IDS] ⚠️ Comportamiento inconsistente — IPS/WAF dinámico probable")
    else:
        itype = "Sin filtrado detectado"
        evasion = "No se requiere evasión — objetivo accesible directamente."
        log(f"  [IDS] ✓ Sin firewall restrictivo detectado")

    return {
        "type":                  itype,
        "firewall_detected":     all_blocked,
        "ips_waf_suspected":     inconsistent,
        "probe_responses":       responses,
        "evasion_recommendation": evasion,
    }


def run_nmap_scan(
    target,
    profile,
    log_fn=None,
    enable_nse: bool = False,
    enable_cve: bool = False,
    enable_ids: bool = False,
    zombie_host: str = "",
):
    log = log_fn or _noop

    # ── Validate inputs ──────────────────────────────────────────────────────
    try:
        target = _sanitize_target(target)
    except ValueError as e:
        log(f"[!] Input inválido: {e}")
        return {"error": str(e)}

    if zombie_host and zombie_host.strip():
        try:
            zombie_host = _sanitize_target(zombie_host)
        except ValueError as e:
            log(f"[!] Zombie host inválido: {e}")
            return {"error": str(e)}

    # ── Build base arguments ─────────────────────────────────────────────────
    if zombie_host and zombie_host.strip():
        args = f"-sI {zombie_host} -p 1-1024"
        mode = "Idle Scan (Zombie)"
    elif profile == "Rápido (Top 100)":
        args = "-F"
        mode = "Rápido"
    elif profile == "Agresivo (Full Scan)":
        args = "-sV -sC -O -T4"
        mode = "Agresivo"
    elif profile == "Sigiloso (SYN Scan)":
        args = "-sS -sV -T2 --max-retries 2"
        mode = "Sigiloso"
    elif profile == "Completo (All Ports)":
        args = "-sV -p- -T4"
        mode = "Completo"
    else:
        args = "-F"
        mode = "Rápido"

    raw_command = f"nmap {args} {target}"
    log(f"[*] === SENTINEL-NMAP ===")
    log(f"[*] Objetivo  : {target}")
    log(f"[*] Modo      : {mode}")
    log(f"[*] Comando   : {raw_command}")
    if enable_nse:
        log(f"[*] NSE Chain : HABILITADO")
    if enable_cve:
        log(f"[*] CVE Lookup: HABILITADO (NIST NVD API)")
    if enable_ids:
        log(f"[*] IDS/WAF   : HABILITADO")
    log("[*] Ejecutando escaneo...")

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments=args, timeout=300)

        if not nm.all_hosts():
            log(f"[!] {target} no responde o está inactivo.")
            return {"error": f"El objetivo {target} no responde o no está activo."}

        scan_data = {
            "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tool":        "Sentinel-Nmap",
            "target":      target,
            "mode":        mode,
            "raw_command": raw_command,
            "hosts":       [],
            "nse_results": [],
            "cve_findings": [],
            "ids_waf":     {},
        }

        hosts_found = nm.all_hosts()
        log(f"[+] {len(hosts_found)} host(s) activo(s)")

        for host in hosts_found:
            os_match   = nm[host].get("osmatch", [])
            os_detected = os_match[0].get("name", "Desconocido") if os_match else "Desconocido"
            log(f"[+] Host: {host} | OS: {os_detected}")

            host_info = {
                "ip":          host,
                "status":      nm[host].state(),
                "hostname":    nm[host].hostname(),
                "os_detected": os_detected,
                "ports":       [],
            }

            open_ports = []
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    svc_data = nm[host][proto][port]
                    svc   = svc_data["name"]
                    prod  = svc_data["product"]
                    ver   = svc_data["version"]
                    state = svc_data["state"]
                    log(f"  [{state}] {port}/{proto} — {svc} {prod} {ver}".rstrip())

                    port_entry = {
                        "port":      port,
                        "state":     state,
                        "service":   svc,
                        "product":   prod,
                        "version":   ver,
                        "extrainfo": svc_data.get("extrainfo", ""),
                        "cves":      [],
                    }

                    # ── CVE Lookup per service ───────────────────────────────
                    if enable_cve and state == "open" and prod:
                        log(f"  [CVE] Buscando CVEs para '{prod} {ver}'...")
                        cves = _lookup_cves(prod, ver, log)
                        port_entry["cves"] = cves
                        if cves:
                            scan_data["cve_findings"].append({
                                "host":    host,
                                "port":    port,
                                "service": svc,
                                "product": f"{prod} {ver}".strip(),
                                "cves":    cves,
                            })

                    host_info["ports"].append(port_entry)
                    if state == "open":
                        open_ports.append(port)

            scan_data["hosts"].append(host_info)

            # ── NSE Chaining ─────────────────────────────────────────────────
            if enable_nse and open_ports:
                interesting = [p for p in open_ports if p in NSE_CHAINS or p in CRITICAL_PORTS]
                if interesting:
                    log(f"\n[*] === FASE NSE: {len(interesting)} puerto(s) con scripts específicos ===")
                    for port in interesting[:10]:
                        nse_result = _run_nse_chain(host, port, log)
                        if nse_result:
                            nse_result["host"] = host
                            scan_data["nse_results"].append(nse_result)

        # ── IDS/WAF Detection ────────────────────────────────────────────────
        if enable_ids:
            log(f"\n")
            ids_result = _detect_ids_waf(target, log)
            scan_data["ids_waf"] = ids_result

        # ── Save to disk ─────────────────────────────────────────────────────
        os.makedirs("data/scans", exist_ok=True)
        filename = f"data/scans/nmap_{target.replace('/', '_').replace(':', '_')}.json"
        with open(filename, "w") as f:
            json.dump(scan_data, f, indent=4)

        log(f"\n[+] Resultados guardados en {filename}")
        total_cves = sum(len(f["cves"]) for f in scan_data["cve_findings"])
        log(f"[+] NSE chains ejecutadas: {len(scan_data['nse_results'])} | CVEs encontrados: {total_cves}")
        log("[+] Escaneo completado.")
        return scan_data

    except Exception as e:
        return {"error": f"Error en la ejecución de Nmap: {str(e)}"}
