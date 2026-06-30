import nmap
import json
import os

def ejecutar_escaneo(target):
    # Inicializamos el scanner
    nm = nmap.PortScanner()
    
    print(f"[*] Iniciando escaneo de seguridad en: {target}")
    
    # -sV: Detección de versiones
    # -O: Detección de Sistema Operativo
    # --top-ports 100: Escanea los 100 puertos más comunes (más rápido para el hackathon)
    nm.scan(hosts=target, arguments='-sV -O --top-ports 100')
    
    resultado_final = []

    for host in nm.all_hosts():
        dict_host = {
            "ip": host,
            "hostname": nm[host].hostname(),
            "estado": nm[host].state(),
            "os": nm[host].get('osmatch', [{}])[0].get('name', 'Desconocido'),
            "servicios": []
        }

        for proto in nm[host].all_protocols():
            puertos = nm[host][proto].keys()
            for port in puertos:
                srv = nm[host][proto][port]
                dict_host["servicios"].append({
                    "puerto": port,
                    "nombre": srv['name'],
                    "producto": srv.get('product', 'N/A'),
                    "version": srv.get('version', 'N/A'),
                    "confianza": srv.get('conf', 'N/A')
                })
        
        resultado_final.append(dict_host)
    
    return resultado_final

if __name__ == "__main__":
    # Aquí puedes poner la IP de tu Windows 10 de prueba o tu propia red
    objetivo = "127.0.0.1" 
    
    data = ejecutar_escaneo(objetivo)
    
    # Guardamos el JSON
    with open("escaneo.json", "w") as f:
        json.dump(data, f, indent=4)
        
    print(f"[+] Escaneo finalizado. Se han encontrado {len(data)} hosts.")
    print("[+] Datos guardados en 'escaneo.json' para procesamiento de IA.")