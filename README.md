<img width="1537" height="893" alt="image" src="https://github.com/user-attachments/assets/5a71f38e-6fba-4a16-8be5-6ae329c0b870" />

# OtsuSearch — AI-Powered Cyber Audit Platform

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-Frontend-red?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Gemini](https://img.shields.io/badge/AI-Gemini_2.5_Flash-brightgreen?logo=google&logoColor=white)](https://aistudio.google.com/)
[![Claude](https://img.shields.io/badge/AI-Claude_Opus-blueviolet?logo=anthropic&logoColor=white)](https://www.anthropic.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker&logoColor=white)](https://www.docker.com/)
[![Nmap](https://img.shields.io/badge/Nmap-Scanner-004170?logo=gnu-bash&logoColor=white)](https://nmap.org/)
[![Scapy](https://img.shields.io/badge/Scapy-Network-black?logo=linux&logoColor=white)](https://scapy.net/)
[![License](https://img.shields.io/badge/License-MIT-green?logo=opensourceinitiative&logoColor=white)](https://opensource.org/licenses/MIT)

---

**OtsuSearch** es una plataforma de auditoría de ciberseguridad que combina motores de escaneo de red con inteligencia artificial (Gemini o Claude) para transformar datos técnicos en reportes ejecutivos accionables. Diseñada para pentesters, auditores y equipos de seguridad que necesitan resultados claros y rápidos.

---

## ¿Qué hace?

OtsuSearch no es solo un escáner de puertos. Analiza la superficie de ataque completa de una red y la interpreta bajo marcos de cumplimiento como **ISO 27001**, **NIST CSF**, **PCI-DSS** y **OWASP**, generando diagnósticos de riesgo y reportes PDF listos para presentar a clientes o directivos.

---

## Módulos

### Escaneo

- **Red (ARP/Scapy)** — Descubrimiento de dispositivos en capa 2, identificación de vendor por MAC (OUI), detección de ARP spoofing y gestión de baseline autorizado
- **Servicios (Nmap)** — Fingerprinting avanzado de puertos, versiones, detección de CVEs, análisis IDS/WAF y técnicas de evasión
- **SSL/TLS** — Verificación de certificados, protocolos obsoletos (SSLv3, TLS 1.0/1.1), HSTS, cipher suites y vulnerabilidades (Heartbleed, POODLE)
- **Email Security** — Validación de registros SPF, DMARC, DKIM, MX y banner SMTP
- **Web** — Enumeración de directorios, análisis de headers de seguridad, detección de secretos expuestos y configuraciones CORS

### Inteligencia Artificial

- Análisis de riesgo con **Google Gemini** o **Anthropic Claude** (configurable)
- Priorización por técnicas **MITRE ATT&CK** y probabilidad **EPSS**
- Proyección de **movimiento lateral** con diagrama de infiltración
- Generación de **scripts de remediación** (Bash/PowerShell) listos para ejecutar
- **Knowledge Base RAG** — consulta documentos internos (PDFs de normativas) con contexto del escaneo
- Reporte ejecutivo **PDF corporativo** con score de riesgo

---

## Stack

| Componente | Tecnología |
|---|---|
| Frontend | [Streamlit](https://streamlit.io/) |
| AI Engine | [Google Gemini](https://aistudio.google.com/) / [Anthropic Claude](https://www.anthropic.com/) |
| Escaneo de red | [Scapy](https://scapy.net/) + [Nmap](https://nmap.org/) |
| Visualización | Plotly + ECharts |
| Contenedores | [Docker](https://www.docker.com/) |

---

## Instalación

### Requisitos

- Linux (Kali, Ubuntu o Debian)
- Docker + Docker Compose
- API Key de [Google AI Studio](https://aistudio.google.com/) **o** [Anthropic](https://console.anthropic.com/) (o ambas)

### Despliegue con Docker

```bash
git clone https://github.com/diegomty/OtsuSearch.git
cd OtsuSearch
cp data/config.json.example data/config.json
# Edita data/config.json y agrega tu(s) API key(s)
chmod +x setup.sh
sudo ./setup.sh
```

La app estará disponible en `http://localhost:8501`

### Ejecución directa (sin Docker)

```bash
git clone https://github.com/diegomty/OtsuSearch.git
cd OtsuSearch
cp data/config.json.example data/config.json
# Edita data/config.json y agrega tu(s) API key(s)
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo venv/bin/python -m streamlit run app.py
```

> **Nota:** Scapy y Nmap requieren privilegios de root para enviar paquetes crudos. Usa `sudo` al lanzar la app si planeas usar los módulos de red.

---

## Configuración

Copia el archivo de ejemplo y completa tus claves:

```bash
cp data/config.json.example data/config.json
```

```json
{
    "gemini_key": "TU_GEMINI_API_KEY",
    "anthropic_key": "TU_ANTHROPIC_API_KEY",
    "ai_provider": "gemini",
    "model": "gemini-2.5-flash",
    "claude_model": "claude-opus-4-7"
}
```

El archivo `data/config.json` está en `.gitignore` — nunca se sube al repositorio.

---

## Contribuir

1. Haz fork del repo
2. Crea una rama: `git checkout -b feature/mi-mejora`
3. Haz tus cambios y abre un Pull Request

---

## Licencia

MIT — libre para usar, modificar y distribuir.
