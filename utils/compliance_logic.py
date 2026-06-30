# utils/compliance_logic.py

def get_compliance_mapping():
    """Retorna una base de conocimientos de puertos vs normativas."""
    return {
        "21": {
            "service": "FTP",
            "iso_27001": "Control A.8.24 (Seguridad en servicios de red)",
            "nist": "NIST SP 800-53 (SC-8: Transmission Confidentiality)",
            "risk": "Tráfico no cifrado. Las credenciales viajan en texto plano.",
            "mitigation": "Migrar a SFTP o FTPS utilizando TLS 1.3."
        },
        "22": {
            "service": "SSH",
            "iso_27001": "Control A.8.2 (Privilegios de acceso)",
            "nist": "NIST SP 800-53 (AC-17: Remote Access)",
            "risk": "Si no está endurecido, permite fuerza bruta.",
            "mitigation": "Deshabilitar login de root y usar llaves RSA de 4096 bits."
        },
        "23": {
            "service": "Telnet",
            "iso_27001": "Control A.8.24 (Protocolos inseguros)",
            "nist": "NIST SP 800-53 (IA-2: Identification and Authentication)",
            "risk": "Protocolo obsoleto y altamente inseguro.",
            "mitigation": "Cerrar puerto inmediatamente y usar SSH."
        },
        "80": {
            "service": "HTTP",
            "iso_27001": "Control A.8.24 (Uso de protocolos de comunicación)",
            "nist": "NIST SP 800-53 (SC-13: Cryptography)",
            "risk": "Comunicación web sin cifrar.",
            "mitigation": "Implementar HSTS y redirigir todo el tráfico al puerto 443 (HTTPS)."
        },
        "3389": {
            "service": "RDP",
            "iso_27001": "Control A.5.15 (Seguridad en teletrabajo)",
            "nist": "NIST SP 800-53 (AC-3: Access Enforcement)",
            "risk": "Escritorio remoto expuesto; vector principal de Ransomware.",
            "mitigation": "Cerrar acceso público y requerir VPN con MFA."
        }
    }

def check_compliance(scan_results):
    """Cruza los resultados del JSON con la base de normativas."""
    mapping = get_compliance_mapping()
    violations = []

    for host in scan_results.get("hosts", []):
        for port_info in host.get("ports", []):
            p = str(port_info["port"])
            if p in mapping:
                violation = {
                    "ip": host["ip"],
                    "port": p,
                    **mapping[p]
                }
                violations.append(violation)
    
    return violations 