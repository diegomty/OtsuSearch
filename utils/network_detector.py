import platform
import socket
import ipaddress
import shutil
import os


def get_os() -> str:
    return platform.system()  # 'Windows' | 'Linux' | 'Darwin'


def get_active_network() -> tuple[str | None, str]:
    """
    Returns (interface_name, subnet_cidr) for the machine's active network.
    Uses netifaces when available, falls back to socket trick.
    """
    try:
        import netifaces
        gws = netifaces.gateways()
        default = gws.get('default', {}).get(netifaces.AF_INET)
        if default:
            iface = default[1]
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                ip   = addrs[netifaces.AF_INET][0]['addr']
                mask = addrs[netifaces.AF_INET][0]['netmask']
                net  = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                return iface, str(net)
    except Exception:
        pass

    # Fallback: UDP trick — finds the IP used to reach the internet
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return None, str(net)
    except Exception:
        pass

    return None, "192.168.1.0/24"


def check_nmap() -> bool:
    return shutil.which('nmap') is not None


def check_scapy() -> bool:
    try:
        from scapy.all import conf  # noqa: F401
        return True
    except Exception:
        return False


def check_admin() -> bool:
    try:
        if get_os() == 'Windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def check_npcap() -> bool:
    """Windows only — verifies Npcap DLL is present."""
    if get_os() != 'Windows':
        return True  # not needed on Linux/Mac
    return os.path.exists(r'C:\Windows\System32\Npcap\wpcap.dll')


def get_setup_guide() -> dict:
    """
    Returns a dict of issues → install instructions for the current OS.
    Empty dict means everything is ready.
    """
    sys = get_os()
    guide = {}

    if not check_nmap():
        if sys == 'Windows':
            guide['nmap'] = {
                'title': 'Nmap no instalado',
                'detail': 'Requerido para el escáner de servicios y puertos.',
                'fix': 'Descarga desde https://nmap.org/download.html  (marca "Add to PATH")',
                'cmd': None,
            }
        elif sys == 'Darwin':
            guide['nmap'] = {
                'title': 'Nmap no instalado',
                'detail': 'Requerido para el escáner de servicios y puertos.',
                'fix': 'brew install nmap',
                'cmd': 'brew install nmap',
            }
        else:
            guide['nmap'] = {
                'title': 'Nmap no instalado',
                'detail': 'Requerido para el escáner de servicios y puertos.',
                'fix': 'sudo apt install nmap -y',
                'cmd': 'sudo apt install nmap -y',
            }

    if sys == 'Windows' and not check_npcap():
        guide['npcap'] = {
            'title': 'Npcap no instalado',
            'detail': 'Requerido por Scapy para el escaneo ARP en Windows.',
            'fix': 'Descarga desde https://npcap.com/  (activa "WinPcap API-compatible Mode")',
            'cmd': None,
        }

    if not check_admin():
        if sys == 'Windows':
            guide['admin'] = {
                'title': 'Sin privilegios de administrador',
                'detail': 'Nmap y Scapy necesitan permisos elevados para enviar paquetes raw.',
                'fix': 'Click derecho en Terminal → "Ejecutar como administrador" → relanza la app',
                'cmd': None,
            }
        else:
            guide['admin'] = {
                'title': 'Sin privilegios root',
                'detail': 'Scapy (ARP scan) necesita root para enviar paquetes raw.',
                'fix': 'sudo python -m streamlit run app.py',
                'cmd': 'sudo python -m streamlit run app.py',
            }

    return guide


def get_scapy_iface(friendly_name: str | None) -> str | None:
    """
    Converts a friendly interface name to the format Scapy expects.
    On Windows, Scapy uses GUID-style names via Npcap; conf.iface handles
    this automatically when we pass None.
    """
    if not friendly_name:
        return None  # let Scapy auto-select via conf.iface

    if get_os() == 'Windows':
        try:
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                if (friendly_name.lower() in iface.get('name', '').lower() or
                        friendly_name.lower() in iface.get('description', '').lower()):
                    return iface.get('name')
        except Exception:
            pass
        return None  # fallback: let Scapy auto-select

    return friendly_name  # Linux/macOS: name is usable directly
