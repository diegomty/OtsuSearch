from scapy.all import ARP, Ether, ICMP, IP, srp, sr1, sniff, conf as scapy_conf
import json
import os
import socket
import datetime

# ── OUI: IEEE first 3 bytes → vendor (uppercase, colon-sep) ─────────────────
_OUI_DB = {
    # Virtualization
    "00:50:56": "VMware",       "00:0C:29": "VMware",       "00:05:69": "VMware",
    "00:15:5D": "Microsoft Hyper-V", "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    # Apple
    "00:03:93": "Apple",        "00:0A:27": "Apple",        "00:11:24": "Apple",
    "00:14:51": "Apple",        "00:16:CB": "Apple",        "00:17:F2": "Apple",
    "00:1E:C2": "Apple",        "3C:22:FB": "Apple",        "A4:C3:61": "Apple",
    "F0:D1:A9": "Apple",        "DC:A6:32": "Raspberry Pi", "B8:27:EB": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    # Cisco
    "00:17:42": "Cisco",        "00:1B:D4": "Cisco",        "00:50:0F": "Cisco",
    "70:81:05": "Cisco",        "00:00:0C": "Cisco",        "00:1A:A1": "Cisco",
    "00:13:C4": "Cisco",        "00:1C:58": "Cisco",        "58:AC:78": "Cisco",
    # HP
    "00:25:B3": "HP",           "3C:D9:2B": "HP",           "00:1E:4F": "HP",
    "00:1A:4B": "HP",           "FC:15:B4": "HP",           "3C:A8:2A": "HP",
    # Dell
    "00:26:B9": "Dell",         "00:14:22": "Dell",         "18:66:DA": "Dell",
    "14:FE:B5": "Dell",         "00:22:19": "Dell",         "BC:30:5B": "Dell",
    # Intel
    "00:1B:21": "Intel",        "8C:8D:28": "Intel",        "94:65:9C": "Intel",
    "00:23:14": "Intel",        "AC:FD:CE": "Intel",        "28:D2:44": "Intel",
    # Samsung
    "00:12:47": "Samsung",      "00:15:B9": "Samsung",      "00:17:C9": "Samsung",
    "00:1A:8A": "Samsung",      "00:21:D2": "Samsung",      "78:25:AD": "Samsung",
    "94:35:0A": "Samsung",      "8C:C8:CD": "Samsung",
    # Xiaomi
    "28:6C:07": "Xiaomi",       "34:80:B3": "Xiaomi",       "50:8F:4C": "Xiaomi",
    "AC:C1:EE": "Xiaomi",       "F4:8B:32": "Xiaomi",       "78:11:DC": "Xiaomi",
    "58:44:98": "Xiaomi",       "64:09:80": "Xiaomi",       "A4:C3:F0": "Xiaomi",
    # Huawei
    "00:18:82": "Huawei",       "00:25:9E": "Huawei",       "04:BD:70": "Huawei",
    "08:19:A6": "Huawei",       "20:08:ED": "Huawei",       "48:00:31": "Huawei",
    "54:A5:1B": "Huawei",       "5C:C3:07": "Huawei",       "70:7B:E8": "Huawei",
    "B4:15:13": "Huawei",       "D4:12:43": "Huawei",       "FC:48:EF": "Huawei",
    "30:D1:7E": "Huawei",       "40:CB:A8": "Huawei",       "CC:96:A0": "Huawei",
    # TP-Link
    "14:CC:20": "TP-Link",      "18:D6:C7": "TP-Link",      "20:F4:1B": "TP-Link",
    "40:16:7E": "TP-Link",      "50:3E:AA": "TP-Link",      "54:E6:FC": "TP-Link",
    "64:70:02": "TP-Link",      "74:DA:38": "TP-Link",      "EC:08:6B": "TP-Link",
    "E8:DE:27": "TP-Link",      "F4:EC:38": "TP-Link",      "B0:4E:26": "TP-Link",
    "C0:4A:00": "TP-Link",      "D4:6E:0E": "TP-Link",
    # ASUS
    "00:1A:92": "ASUS",         "04:92:26": "ASUS",         "14:DA:E9": "ASUS",
    "18:31:BF": "ASUS",         "50:46:5D": "ASUS",         "74:D0:2B": "ASUS",
    "AC:9E:17": "ASUS",         "BC:EE:7B": "ASUS",         "F4:6D:04": "ASUS",
    "2C:FD:A1": "ASUS",         "6C:FD:B9": "ASUS",         "E4:92:FB": "ASUS",
    # Netgear
    "00:09:5B": "Netgear",      "00:0F:B5": "Netgear",      "00:14:6C": "Netgear",
    "20:4E:7F": "Netgear",      "30:46:9A": "Netgear",      "74:44:01": "Netgear",
    "A0:21:B7": "Netgear",      "C4:04:15": "Netgear",      "E4:F4:C6": "Netgear",
    "84:1B:5E": "Netgear",      "6C:B0:CE": "Netgear",
    # Amazon (Alexa/Echo/Fire)
    "18:74:2E": "Amazon",       "34:D2:70": "Amazon",       "44:65:0D": "Amazon",
    "68:37:E9": "Amazon",       "74:75:48": "Amazon",       "84:D6:D0": "Amazon",
    "CC:F7:35": "Amazon",       "F0:27:2D": "Amazon",       "FC:A1:83": "Amazon",
    "40:B4:CD": "Amazon",       "50:F5:DA": "Amazon",
    # Google (Chromecast/Nest/Home)
    "54:60:09": "Google",       "6C:AD:F8": "Google",       "9C:A9:D7": "Google",
    "E4:F0:42": "Google",       "F4:F5:D8": "Google",       "1A:00:1A": "Google",
    "DC:A6:32": "Google Nest",  "48:D6:D5": "Google",
    # Ubiquiti
    "00:15:6D": "Ubiquiti",     "04:18:D6": "Ubiquiti",     "18:E8:29": "Ubiquiti",
    "24:A4:3C": "Ubiquiti",     "44:D9:E7": "Ubiquiti",     "74:83:C2": "Ubiquiti",
    "DC:9F:DB": "Ubiquiti",     "F0:9F:C2": "Ubiquiti",     "80:2A:A8": "Ubiquiti",
    # Microsoft
    "00:0D:3A": "Microsoft",    "00:1D:D8": "Microsoft",    "28:18:78": "Microsoft",
    "3C:83:75": "Microsoft",    "70:BC:10": "Microsoft",
    # Nintendo
    "00:09:BF": "Nintendo",     "00:16:56": "Nintendo",     "00:17:AB": "Nintendo",
    "00:1F:32": "Nintendo",     "A4:C0:E1": "Nintendo",     "98:B6:E9": "Nintendo",
    # Sony
    "00:01:4A": "Sony",         "00:13:A9": "Sony",         "28:3F:69": "Sony",
    "70:3A:CB": "Sony",         "54:42:49": "Sony",
    # D-Link
    "00:05:5D": "D-Link",       "00:0F:3D": "D-Link",       "14:D6:4D": "D-Link",
    "28:10:7B": "D-Link",       "C8:BE:19": "D-Link",       "1C:7E:E5": "D-Link",
    # Aruba
    "00:0B:86": "Aruba",        "00:24:6C": "Aruba",        "24:DE:C6": "Aruba",
    "70:3A:0E": "Aruba",        "94:B4:0F": "Aruba",
    # Fortinet
    "00:09:0F": "Fortinet",     "00:1B:FC": "Fortinet",     "08:5B:0E": "Fortinet",
    "90:6C:AC": "Fortinet",     "E8:1C:BA": "Fortinet",
    # MikroTik
    "00:0C:42": "MikroTik",     "2C:C8:1B": "MikroTik",     "4C:5E:0C": "MikroTik",
    "6C:3B:6B": "MikroTik",     "B8:69:F4": "MikroTik",     "D4:CA:6D": "MikroTik",
    # Philips Hue / IoT
    "00:17:88": "Philips Hue",  "EC:B5:FA": "Philips Hue",
    # Synology / QNAP (NAS)
    "00:11:32": "Synology",     "00:08:9B": "QNAP",         "24:5E:BE": "QNAP",
}

_TTL_OS_MAP = [
    ((60, 70),  "Linux/Android"),
    ((120, 130), "Windows"),
    ((250, 256), "Cisco/Router"),
    ((30, 35),   "Solaris/AIX"),
    ((110, 120), "FreeBSD/macOS"),
]

_BASELINE_FILE = "data/baseline.json"
_SCAN_FILE     = "data/scans/last_arp_scan.json"


# ── OUI Lookup ───────────────────────────────────────────────────────────────

def lookup_oui(mac: str) -> str:
    prefix = mac.upper()[:8]
    vendor = _OUI_DB.get(prefix, "")
    if vendor:
        return vendor
    # Optionally load extended local OUI file
    oui_path = "data/oui.json"
    if os.path.exists(oui_path):
        try:
            with open(oui_path) as f:
                ext = json.load(f)
            return ext.get(prefix, "Desconocido")
        except Exception:
            pass
    return "Desconocido"


# ── Baseline management ──────────────────────────────────────────────────────

def load_baseline() -> dict:
    if os.path.exists(_BASELINE_FILE):
        try:
            with open(_BASELINE_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"authorized_macs": {}, "last_updated": None}


def save_baseline(devices: list):
    """Save a list of device dicts as the authorized baseline."""
    os.makedirs("data", exist_ok=True)
    baseline = load_baseline()
    for d in devices:
        mac = d["mac"].lower()
        baseline["authorized_macs"][mac] = {
            "alias": d.get("alias", d.get("hostname", d.get("vendor", ""))),
            "ip_last_seen": d["ip"],
            "vendor": d.get("vendor", ""),
        }
    baseline["last_updated"] = datetime.datetime.now().isoformat()
    with open(_BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)


def remove_from_baseline(mac: str):
    baseline = load_baseline()
    baseline["authorized_macs"].pop(mac.lower(), None)
    with open(_BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)


def check_baseline(devices: list) -> dict:
    baseline = load_baseline()
    if not baseline["authorized_macs"]:
        return {"status": "no_baseline", "new": [], "missing": [], "authorized": []}

    authorized = set(baseline["authorized_macs"].keys())
    current_macs = {d["mac"].lower() for d in devices}

    new_devices   = [d for d in devices if d["mac"].lower() not in authorized]
    missing_macs  = authorized - current_macs
    auth_devices  = [d for d in devices if d["mac"].lower() in authorized]

    missing_detail = [
        {**baseline["authorized_macs"].get(m, {}), "mac": m}
        for m in missing_macs
    ]

    return {
        "status": "checked",
        "new": new_devices,
        "missing": missing_detail,
        "authorized": auth_devices,
        "last_baseline": baseline["last_updated"],
    }


# ── ARP Spoofing / MITM detection ────────────────────────────────────────────

def detect_arp_spoofing(devices: list) -> list:
    alerts = []
    ip_to_macs  = {}
    mac_to_ips  = {}

    for d in devices:
        ip  = d["ip"]
        mac = d["mac"].lower()
        ip_to_macs.setdefault(ip, []).append(mac)
        mac_to_ips.setdefault(mac, []).append(ip)

    for ip, macs in ip_to_macs.items():
        if len(set(macs)) > 1:
            alerts.append({
                "type": "IP_CONFLICT",
                "severity": "CRITICO",
                "detail": f"IP {ip} responde desde {len(macs)} MACs distintas: {', '.join(set(macs))}",
                "indicator": "ARP Poisoning / MITM activo"
            })

    for mac, ips in mac_to_ips.items():
        if len(set(ips)) > 1:
            alerts.append({
                "type": "MAC_DUPLICADA",
                "severity": "ALTO",
                "detail": f"MAC {mac} reclama {len(ips)} IPs: {', '.join(set(ips))}",
                "indicator": "IP Hijacking / suplantación"
            })

    # Cross-scan: check if a known IP now responds with a different MAC
    if os.path.exists(_SCAN_FILE):
        try:
            with open(_SCAN_FILE) as f:
                prev = json.load(f)
            prev_map = {d["ip"]: d["mac"].lower() for d in prev.get("devices", [])}
            for d in devices:
                prev_mac = prev_map.get(d["ip"])
                if prev_mac and prev_mac != d["mac"].lower():
                    alerts.append({
                        "type": "MAC_CHANGED",
                        "severity": "CRITICO",
                        "detail": f"IP {d['ip']}: MAC anterior={prev_mac}, actual={d['mac']}",
                        "indicator": "Posible suplantación de dispositivo entre escaneos"
                    })
        except Exception:
            pass

    return alerts


# ── TTL-based OS hint ────────────────────────────────────────────────────────

def ttl_os_hint(ip: str) -> str:
    try:
        pkt = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
        if pkt and pkt.haslayer(IP):
            ttl = pkt[IP].ttl
            for (low, high), os_name in _TTL_OS_MAP:
                if low <= ttl <= high:
                    return f"{os_name} (TTL={ttl})"
            return f"Desconocido (TTL={ttl})"
    except Exception:
        pass
    return "N/A"


# ── Reverse DNS ──────────────────────────────────────────────────────────────

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ── Network delta ────────────────────────────────────────────────────────────

def _compute_delta(current_devices: list) -> dict:
    if not os.path.exists(_SCAN_FILE):
        return {"new": [], "disappeared": [], "status": "first_scan"}
    try:
        with open(_SCAN_FILE) as f:
            prev = json.load(f)
        prev_ips  = {d["ip"] for d in prev.get("devices", [])}
        curr_ips  = {d["ip"] for d in current_devices}
        new_devs  = [d for d in current_devices if d["ip"] not in prev_ips]
        gone_devs = [d for d in prev.get("devices", []) if d["ip"] not in curr_ips]
        return {"status": "ok", "new": new_devs, "disappeared": gone_devs}
    except Exception:
        return {"new": [], "disappeared": [], "status": "error"}


# ── Active ARP scan ──────────────────────────────────────────────────────────

def run_arp_scan(interface=None, target_range="192.168.1.0/24", log_fn=None,
                 ttl_fingerprint=False, resolve_hostnames=False):
    def log(msg):
        if log_fn:
            log_fn(msg)

    if not interface:
        interface = str(scapy_conf.iface)

    log(f"[*] Iniciando escaneo ARP")
    log(f"[*] Interfaz: {interface} | Rango: {target_range}")
    log("[*] Enviando paquetes ARP broadcast (timeout 3s)...")

    try:
        arp    = ARP(pdst=target_range)
        ether  = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(ether/arp, timeout=3, verbose=0, iface=interface)[0]

        discovered_hosts = []
        for _, received in result:
            vendor = lookup_oui(received.hwsrc)
            entry  = {"ip": received.psrc, "mac": received.hwsrc, "vendor": vendor}

            if resolve_hostnames:
                hn = resolve_hostname(received.psrc)
                entry["hostname"] = hn
                log(f"  [+] {received.psrc}  {received.hwsrc}  [{vendor}]  {hn or 'sin hostname'}")
            else:
                log(f"  [+] {received.psrc}  {received.hwsrc}  [{vendor}]")

            if ttl_fingerprint:
                hint = ttl_os_hint(received.psrc)
                entry["os_hint"] = hint
                log(f"      OS Hint: {hint}")

            discovered_hosts.append(entry)

        if not discovered_hosts:
            log("[!] No se encontraron hosts activos en el rango")

        spoof_alerts    = detect_arp_spoofing(discovered_hosts)
        baseline_report = check_baseline(discovered_hosts)
        delta           = _compute_delta(discovered_hosts)

        for alert in spoof_alerts:
            log(f"  [!!] {alert['severity']}: {alert['detail']}")
        for new_dev in baseline_report.get("new", []):
            log(f"  [ALERTA] Dispositivo NO autorizado: {new_dev['ip']} / {new_dev['mac']}")
        for nd in delta.get("new", []):
            log(f"  [DELTA] Nuevo en red: {nd['ip']} ({nd.get('vendor','')})")
        for gd in delta.get("disappeared", []):
            log(f"  [DELTA] Desapareció: {gd['ip']} ({gd.get('vendor','')})")

        os.makedirs("data/scans", exist_ok=True)
        output = {
            "tool":                "Sentinel-Scapy",
            "mode":                "active",
            "interface":           interface,
            "hosts_found":         len(discovered_hosts),
            "devices":             discovered_hosts,
            "arp_spoofing_alerts": spoof_alerts,
            "baseline_report":     baseline_report,
            "delta":               delta,
        }
        with open(_SCAN_FILE, "w") as f:
            json.dump(output, f, indent=4)

        log(f"[+] Completado — {len(discovered_hosts)} host(s)")
        if spoof_alerts:
            log(f"[!!] {len(spoof_alerts)} alerta(s) ARP Spoofing detectadas!")
        if baseline_report.get("new"):
            log(f"[!!] {len(baseline_report['new'])} dispositivo(s) NO autorizados!")
        return output

    except Exception as e:
        log(f"[!] Error: {str(e)}")
        return {"error": f"Error de permisos o red: {str(e)}. (¿Ejecutaste con sudo?)"}


# ── Passive sniff mode ───────────────────────────────────────────────────────

def run_passive_sniff(interface=None, duration=30, log_fn=None):
    """Discovers devices by listening to ARP traffic — zero packets sent."""
    def log(msg):
        if log_fn:
            log_fn(msg)

    if not interface:
        interface = str(scapy_conf.iface)

    log(f"[*] MODO PASIVO — escuchando tráfico ARP por {duration}s")
    log(f"[*] Interfaz: {interface} | Sin enviar paquetes (100% silencioso)")

    seen = {}

    def _handle(pkt):
        if pkt.haslayer(ARP) and pkt[ARP].op in (1, 2):
            ip  = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip and mac and ip != "0.0.0.0" and ip not in seen:
                seen[ip] = mac
                vendor = lookup_oui(mac)
                log(f"  [+] {ip}  {mac}  [{vendor}]")

    try:
        sniff(iface=interface, filter="arp", prn=_handle, timeout=duration, store=0)
    except Exception as e:
        log(f"[!] Error en sniff pasivo: {str(e)}")
        return {"error": str(e)}

    devices         = [{"ip": ip, "mac": mac, "vendor": lookup_oui(mac)} for ip, mac in seen.items()]
    spoof_alerts    = detect_arp_spoofing(devices)
    baseline_report = check_baseline(devices)
    delta           = _compute_delta(devices)

    log(f"[+] Sniff pasivo completado — {len(devices)} dispositivos detectados")
    if spoof_alerts:
        log(f"[!!] {len(spoof_alerts)} alerta(s) ARP Spoofing!")
    if baseline_report.get("new"):
        log(f"[!!] {len(baseline_report['new'])} dispositivo(s) NO autorizados!")

    os.makedirs("data/scans", exist_ok=True)
    output = {
        "tool":                "Sentinel-Scapy",
        "mode":                "passive",
        "interface":           interface,
        "duration_seconds":    duration,
        "hosts_found":         len(devices),
        "devices":             devices,
        "arp_spoofing_alerts": spoof_alerts,
        "baseline_report":     baseline_report,
        "delta":               delta,
    }
    with open(_SCAN_FILE, "w") as f:
        json.dump(output, f, indent=4)

    return output
