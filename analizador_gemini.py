import json
import os
import re
import time
from google import genai
from google.genai import types
from utils.compliance_logic import check_compliance

try:
    import anthropic as _anthropic_sdk
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False


# ─── Shared prompts ──────────────────────────────────────────────────────────

def _build_nmap_prompt(datos_json):
    violaciones = check_compliance(datos_json)
    return f"""
ERES: Senior Cyber Threat Intelligence Lead.
TU MISIÓN: Evaluar la superficie de ataque y priorizar la remediación.

DATOS TÉCNICOS:
{json.dumps(datos_json, indent=2)}

VIOLACIONES DE NORMATIVA DETECTADAS:
{json.dumps(violaciones, indent=2)}

REGLAS ADICIONALES PARA EL ANÁLISIS:
1. PUNTUACIÓN EPSS: Estima la probabilidad de explotación de cada servicio (Muy Alta, Alta, Media, Baja).
2. TÉCNICAS MITRE ATT&CK: Relaciona los puertos abiertos con posibles técnicas de adversarios (ej. T1190 - Exploit Public-Facing Application).
3. PRIORIZACIÓN ESTRATÉGICA: Clasifica los hallazgos en: "Corregir en < 24h", "Corregir en < 7 días", "Monitorear".
4. IMPACTO DE NEGOCIO: ¿Cómo afectaría esto a la continuidad de la empresa?
5. Genera un formato Markdown elegante y profesional.
6. Para cada host, crea una tabla de resumen de puertos con: Puerto | Servicio | EPSS | MITRE ATT&CK | Acción Recomendada.
7. IMPORTANTE: No generes tablas en formato Markdown (con barras |). En su lugar, usa listas numeradas o puntos claros. No uses demasiados asteriscos.
8. Al final de tu análisis, incluye una frase corta llamada 'Impacto Financiero Estimado' donde expliques qué pasaría si hackean esos puertos (ej: Robo de datos de clientes, caída de la página por 48 horas, etc.).
"""


def _build_audit_prompt(nmap_data, scapy_data, web_data):
    return f"""
ERES: Senior Cyber-Security Auditor & Threat Hunter.
TU MISIÓN: Realizar un informe ejecutivo consolidado basado en múltiples fuentes de escaneo.

═══════════════════════════════════════════════════════════════
DATOS TÉCNICOS CONSOLIDADOS
═══════════════════════════════════════════════════════════════

1. RED (Descubrimiento Scapy - ARP):
{json.dumps(scapy_data, indent=2) if scapy_data else "Sin datos de red"}

2. SERVICIOS (Auditoría Nmap - Puertos & Versiones):
{json.dumps(nmap_data, indent=2) if nmap_data else "Sin datos de servicios"}

3. APLICACIONES WEB (Enumeración Web - Directorios & Headers):
{json.dumps(web_data, indent=2) if web_data else "Sin datos web"}

═══════════════════════════════════════════════════════════════
ESTRUCTURA REQUERIDA DEL INFORME
═══════════════════════════════════════════════════════════════

📊 RESUMEN EJECUTIVO
- Estado general de riesgo (Crítico / Alto / Medio / Bajo)
- Número de dispositivos, servicios vulnerables y directorios expuestos
- Puntuación de madurez de seguridad

🚨 VULNERABILIDADES CRÍTICAS
Para cada hallazgo:
• Servicio/Tecnología identificada
• Puerto y versión vulnerable
• Impacto potencial
• Técnica MITRE ATT&CK asociada

🛠️ RECOMENDACIONES TÉCNICAS PRIORIZADAS
1. Corregir en < 24 horas (Riesgo Crítico)
2. Corregir en < 7 días (Riesgo Alto)
3. Monitorear continuamente (Riesgo Medio)

📈 MATRIZ DE RIESGO
Basada en probabilidad de explotación (EPSS) y criticidad del activo

✅ CONCLUSIÓN
- Nivel de madurez de ciberseguridad actual
- Postura relativa a NIST CSF
- Siguiente paso recomendado

═══════════════════════════════════════════════════════════════
INSTRUCCIONES ESPECÍFICAS
═══════════════════════════════════════════════════════════════

• NO generes tablas con barras (|). Usa listas numeradas o puntos.
• Sé técnico pero accesible para ejecutivos.
• Prioriza la explotabilidad real sobre la existencia teórica.
• Considera la correlación entre hallazgos (ej. SSH abierto + versión antigua).
• Si faltan datos de alguna fuente, menciona qué análisis no fue posible completar.
• Formato: Markdown limpio, sin exceso de símbolos decorativos.
"""


def _build_lateral_prompt(servicios):
    return f"""Eres un Red Team Senior simulando un ataque APT.

SERVICIOS DESCUBIERTOS:
{json.dumps(servicios, indent=2)}

TAREA 1 — ANÁLISIS DE MOVIMIENTO LATERAL:
Proyecta cómo un atacante se movería por esta red. Para cada paso incluye:
- Punto de entrada inicial (servicio más vulnerable)
- Cómo se pivota de un servicio a otro
- Probabilidad estimada de éxito (%)
- Técnica MITRE ATT&CK aplicada

TAREA 2 — JSON ESTRUCTURADO:
Al FINAL de tu respuesta incluye un bloque JSON con exactamente este formato (sin texto adicional después del bloque):

```json
{{
  "pasos": [
    {{
      "paso": 1,
      "desde": "Atacante externo",
      "hacia": "IP:PUERTO/servicio",
      "via": "Método de ataque",
      "probabilidad": 85,
      "tecnica": "T1190 - Exploit Public-Facing Application"
    }}
  ]
}}
```

REGLAS:
- Máximo 6 pasos de movimiento lateral
- Usa IPs y puertos reales de los datos proporcionados
- "probabilidad" es un entero 0-100
- Formato Markdown limpio para el análisis narrativo
- El JSON debe ser válido y parseable"""


def _build_remediation_prompt(scan_data):
    port_lines = []
    for host in scan_data.get('hosts', []):
        for p in host.get('ports', []):
            product = f"{p.get('product','')} {p.get('version','')}".strip() or "desconocido"
            port_lines.append(
                f"  - Puerto {p['port']}/{p.get('service','?')} | Producto: {product} | Host: {host['ip']}"
            )
    if not port_lines:
        return None, []
    target = scan_data.get('target', 'objetivo')
    ports_str = "\n".join(port_lines)
    prompt = f"""Eres un experto en hardening de sistemas Linux y Windows.

Se detectaron los siguientes servicios expuestos en el objetivo {target}:
{ports_str}

TAREA: Genera scripts de remediación inmediata para cada servicio. Sigue EXACTAMENTE este formato:

### [SERVICIO] — Puerto [N] — [CRÍTICO|ALTO|MEDIO]
> Una línea describiendo el riesgo concreto.

**Linux (Bash)**
```bash
#!/bin/bash
# Comandos aquí
```

**Windows (PowerShell)**
```powershell
# Comandos aquí
```

REGLAS:
- Scripts listos para copiar y ejecutar, sin placeholders genéricos.
- Incluye: deshabilitar el servicio si no es necesario, regla de firewall para bloquear el puerto, y hardening mínimo si debe mantenerse abierto.
- Bash: usa ufw/iptables + systemctl. PowerShell: usa netsh/Set-NetFirewallRule + Stop-Service.
- Comenta cada comando con una línea explicando qué hace.
- Cubre TODOS los puertos listados, sin omitir ninguno."""
    return prompt, port_lines


# ─── Gemini helpers ──────────────────────────────────────────────────────────

def _gemini_config(temp):
    return types.GenerateContentConfig(
        temperature=temp,
        safety_settings=[
            types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH",       threshold="OFF"),
            types.SafetySetting(category="HARM_CATEGORY_HARASSMENT",        threshold="OFF"),
            types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="OFF"),
            types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="OFF"),
        ]
    )


def _gemini_generate(client, model_name, system, prompt, temp):
    cfg = types.GenerateContentConfig(
        system_instruction=system,
        temperature=temp,
        safety_settings=[
            types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH",       threshold="OFF"),
            types.SafetySetting(category="HARM_CATEGORY_HARASSMENT",        threshold="OFF"),
            types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="OFF"),
            types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="OFF"),
        ]
    )
    for intento in range(3):
        try:
            response = client.models.generate_content(model=model_name, contents=prompt, config=cfg)
            return response.text
        except Exception as e:
            msg = str(e)
            if "503" in msg or "UNAVAILABLE" in msg:
                if intento < 2:
                    espera = (intento + 1) * 8
                    print(f"[!] Gemini 503 — reintentando en {espera}s (intento {intento+1}/3)...")
                    time.sleep(espera)
                    continue
            raise


# ─── Claude helpers ──────────────────────────────────────────────────────────

def _claude_generate(api_key, model_name, system, prompt, temp):
    if not _ANTHROPIC_AVAILABLE:
        raise RuntimeError("Paquete 'anthropic' no instalado. Ejecuta: pip install anthropic")
    client = _anthropic_sdk.Anthropic(api_key=api_key)
    msg = client.messages.create(
        model=model_name,
        max_tokens=8096,
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text


# ─── Public API ──────────────────────────────────────────────────────────────

def cargar_datos_escaneo(archivo):
    if not os.path.exists(archivo):
        raise FileNotFoundError(f"No se encontró el archivo {archivo}")
    with open(archivo, "r") as f:
        return json.load(f)


def analizar_con_gemini(datos_json, api_key=None, model_name="gemini-2.5-flash", temp=0.3):
    if not api_key or api_key.strip() == "":
        return "⚠️ Error: No hay API Key configurada. Ve a 'Settings' y guarda tu clave."
    client = genai.Client(api_key=api_key)
    print("[*] OtsuSearch: Iniciando análisis con Gemini...")
    try:
        return _gemini_generate(
            client, model_name,
            "Actúa como un Auditor de Ciberseguridad experto. Tu lenguaje es profesional, técnico y orientado a la gestión de riesgos.",
            _build_nmap_prompt(datos_json),
            temp,
        )
    except Exception as e:
        err = str(e)
        if "503" in err or "UNAVAILABLE" in err:
            return "⚠️ El modelo Gemini está con alta demanda. Espera unos segundos y vuelve a intentarlo."
        if "404" in err or "not found" in err.lower():
            return f"⚠️ Modelo '{model_name}' no encontrado. Ve a Settings y usa 'gemini-2.5-flash'."
        return f"[!] Error en la generación de contenido: {err}"


def analizar_con_claude(datos_json, api_key=None, model_name="claude-opus-4-7", temp=0.3):
    if not api_key or api_key.strip() == "":
        return "⚠️ Error: No hay Anthropic API Key configurada. Ve a 'Settings' y guarda tu clave."
    print(f"[*] OtsuSearch: Iniciando análisis con Claude ({model_name})...")
    try:
        return _claude_generate(
            api_key, model_name,
            "Actúa como un Auditor de Ciberseguridad experto. Tu lenguaje es profesional, técnico y orientado a la gestión de riesgos.",
            _build_nmap_prompt(datos_json),
            temp,
        )
    except Exception as e:
        return f"[!] Error con Claude: {str(e)}"


def analizar_con_ia(datos_json, provider="gemini", gemini_key=None, anthropic_key=None,
                    model_name=None, temp=0.3):
    """Unified router — delegates to Gemini or Claude based on provider."""
    if provider == "claude":
        mdl = model_name or "claude-opus-4-7"
        return analizar_con_claude(datos_json, api_key=anthropic_key, model_name=mdl, temp=temp)
    else:
        mdl = model_name or "gemini-2.5-flash"
        return analizar_con_gemini(datos_json, api_key=gemini_key, model_name=mdl, temp=temp)


# ─── Full audit ──────────────────────────────────────────────────────────────

def analizar_auditoria_completa(nmap_data, scapy_data, web_data, api_key=None,
                                model_name="gemini-2.5-flash", temp=0.3):
    if not api_key or api_key.strip() == "":
        return "⚠️ Error: No hay API Key configurada. Ve a 'Settings' y guarda tu clave."
    client = genai.Client(api_key=api_key)
    print("[*] OtsuSearch: Consolidando análisis multimodal (Gemini)...")
    try:
        return _gemini_generate(
            client, model_name,
            "Eres un Auditor de Ciberseguridad Senior con experiencia en pentesting, cumplimiento normativo y gestión de riesgos. Tu objetivo es generar reportes ejecutivos claros, técnicos y accionables.",
            _build_audit_prompt(nmap_data, scapy_data, web_data),
            temp,
        )
    except Exception as e:
        return f"[!] Error crítico en análisis consolidado: {str(e)}"


def analizar_auditoria_completa_claude(nmap_data, scapy_data, web_data, api_key=None,
                                       model_name="claude-opus-4-7", temp=0.3):
    if not api_key or api_key.strip() == "":
        return "⚠️ Error: No hay Anthropic API Key configurada. Ve a 'Settings' y guarda tu clave."
    print(f"[*] OtsuSearch: Consolidando análisis multimodal (Claude)...")
    try:
        return _claude_generate(
            api_key, model_name,
            "Eres un Auditor de Ciberseguridad Senior con experiencia en pentesting, cumplimiento normativo y gestión de riesgos. Tu objetivo es generar reportes ejecutivos claros, técnicos y accionables.",
            _build_audit_prompt(nmap_data, scapy_data, web_data),
            temp,
        )
    except Exception as e:
        return f"[!] Error crítico en análisis consolidado (Claude): {str(e)}"


def analizar_auditoria_ia(nmap_data, scapy_data, web_data, provider="gemini",
                          gemini_key=None, anthropic_key=None, model_name=None, temp=0.3):
    """Unified audit router."""
    if provider == "claude":
        mdl = model_name or "claude-opus-4-7"
        return analizar_auditoria_completa_claude(nmap_data, scapy_data, web_data,
                                                  api_key=anthropic_key, model_name=mdl, temp=temp)
    else:
        mdl = model_name or "gemini-2.5-flash"
        return analizar_auditoria_completa(nmap_data, scapy_data, web_data,
                                           api_key=gemini_key, model_name=mdl, temp=temp)


# ─── Lateral movement ────────────────────────────────────────────────────────

def _extract_lateral_pasos(texto):
    pasos = []
    json_match = re.search(r'```json\s*(\{.*?\})\s*```', texto, re.S)
    if json_match:
        try:
            parsed = json.loads(json_match.group(1))
            pasos = parsed.get("pasos", [])
            texto = texto[:json_match.start()].strip()
        except json.JSONDecodeError:
            pass
    return texto, pasos


def analizar_movimiento_lateral(scan_data, api_key=None, model_name="gemini-2.5-flash", temp=0.3):
    if not api_key or api_key.strip() == "":
        return {"markdown": "⚠️ API Key no configurada.", "pasos": []}

    servicios = []
    for host in scan_data.get("hosts", []):
        for p in host.get("ports", []):
            if p.get("state") == "open":
                servicios.append({
                    "host": host["ip"],
                    "port": p["port"],
                    "service": p["service"],
                    "product": f"{p.get('product','')} {p.get('version','')}".strip(),
                })

    if not servicios:
        return {"markdown": "No hay servicios abiertos para analizar.", "pasos": []}

    client = genai.Client(api_key=api_key)
    try:
        cfg = types.GenerateContentConfig(
            system_instruction="Eres un Red Team operator experto en TTPs y movimiento lateral. Generas análisis técnicos precisos con visualización JSON.",
            temperature=temp,
            safety_settings=[
                types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH",       threshold="OFF"),
                types.SafetySetting(category="HARM_CATEGORY_HARASSMENT",        threshold="OFF"),
                types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="OFF"),
                types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="OFF"),
            ]
        )
        response = client.models.generate_content(model=model_name,
                                                  contents=_build_lateral_prompt(servicios),
                                                  config=cfg)
        texto, pasos = _extract_lateral_pasos(response.text)
        return {"markdown": texto, "pasos": pasos}
    except Exception as e:
        return {"markdown": f"[!] Error: {e}", "pasos": []}


def analizar_movimiento_lateral_claude(scan_data, api_key=None, model_name="claude-opus-4-7", temp=0.3):
    if not api_key or api_key.strip() == "":
        return {"markdown": "⚠️ Anthropic API Key no configurada.", "pasos": []}

    servicios = []
    for host in scan_data.get("hosts", []):
        for p in host.get("ports", []):
            if p.get("state") == "open":
                servicios.append({
                    "host": host["ip"],
                    "port": p["port"],
                    "service": p["service"],
                    "product": f"{p.get('product','')} {p.get('version','')}".strip(),
                })

    if not servicios:
        return {"markdown": "No hay servicios abiertos para analizar.", "pasos": []}

    try:
        texto = _claude_generate(
            api_key, model_name,
            "Eres un Red Team operator experto en TTPs y movimiento lateral. Generas análisis técnicos precisos con visualización JSON.",
            _build_lateral_prompt(servicios),
            temp,
        )
        texto, pasos = _extract_lateral_pasos(texto)
        return {"markdown": texto, "pasos": pasos}
    except Exception as e:
        return {"markdown": f"[!] Error (Claude): {e}", "pasos": []}


def analizar_movimiento_lateral_ia(scan_data, provider="gemini", gemini_key=None,
                                   anthropic_key=None, model_name=None, temp=0.3):
    """Unified lateral movement router."""
    if provider == "claude":
        mdl = model_name or "claude-opus-4-7"
        return analizar_movimiento_lateral_claude(scan_data, api_key=anthropic_key,
                                                  model_name=mdl, temp=temp)
    else:
        mdl = model_name or "gemini-2.5-flash"
        return analizar_movimiento_lateral(scan_data, api_key=gemini_key,
                                           model_name=mdl, temp=temp)


# ─── Remediation scripts ─────────────────────────────────────────────────────

def generar_scripts_remediacion(scan_data, api_key=None, model_name="gemini-2.5-flash", temp=0.2):
    if not api_key or api_key.strip() == "":
        return "⚠️ Error: No hay API Key configurada. Ve a 'Settings' y guarda tu clave."
    prompt, port_lines = _build_remediation_prompt(scan_data)
    if prompt is None:
        return "No se detectaron puertos abiertos para generar scripts de remediación."
    try:
        client = genai.Client(api_key=api_key)
        return _gemini_generate(
            client, model_name,
            "Eres un ingeniero de seguridad ofensiva y hardening. Generas scripts ejecutables, precisos y seguros.",
            prompt, temp,
        )
    except Exception as e:
        return f"[!] Error al generar scripts: {str(e)}"


def generar_scripts_remediacion_claude(scan_data, api_key=None, model_name="claude-opus-4-7", temp=0.2):
    if not api_key or api_key.strip() == "":
        return "⚠️ Error: No hay Anthropic API Key configurada. Ve a 'Settings' y guarda tu clave."
    prompt, port_lines = _build_remediation_prompt(scan_data)
    if prompt is None:
        return "No se detectaron puertos abiertos para generar scripts de remediación."
    try:
        return _claude_generate(
            api_key, model_name,
            "Eres un ingeniero de seguridad ofensiva y hardening. Generas scripts ejecutables, precisos y seguros.",
            prompt, temp,
        )
    except Exception as e:
        return f"[!] Error al generar scripts (Claude): {str(e)}"


def generar_scripts_ia(scan_data, provider="gemini", gemini_key=None,
                       anthropic_key=None, model_name=None, temp=0.2):
    """Unified remediation scripts router."""
    if provider == "claude":
        mdl = model_name or "claude-opus-4-7"
        return generar_scripts_remediacion_claude(scan_data, api_key=anthropic_key,
                                                  model_name=mdl, temp=temp)
    else:
        mdl = model_name or "gemini-2.5-flash"
        return generar_scripts_remediacion(scan_data, api_key=gemini_key,
                                           model_name=mdl, temp=temp)


if __name__ == "__main__":
    try:
        archivo_buscado = "escaneo.json"
        if not os.path.exists(archivo_buscado):
            print(f"[!] No se encontró '{archivo_buscado}'. Asegúrate de correr el escaneo primero.")
        else:
            datos = cargar_datos_escaneo(archivo_buscado)
            reporte = analizar_con_gemini(datos)

            print("\n" + "="*45)
            print("🛡️ REPORTE DE CUMPLIMIENTO GENERADO")
            print("="*45 + "\n")

            with open("REPORTE_IA.md", "w", encoding="utf-8") as f:
                f.write(reporte)

            print(reporte)
            print(f"\n[+] Análisis completado. El archivo 'REPORTE_IA.md' ha sido actualizado.")

    except Exception as e:
        print(f"[!] Error de ejecución: {e}")
