<img width="1537" height="893" alt="image" src="https://github.com/user-attachments/assets/5a71f38e-6fba-4a16-8be5-6ae329c0b870" />


# 🛡️ Sentinel-Core AI: Advanced Cyber-Audit Suite

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-Frontend-red?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Gemini](https://img.shields.io/badge/AI-Gemini_2.5_Flash-brightgreen?logo=google&logoColor=white)](https://aistudio.google.com/)
[![Docker](https://img.shields.io/badge/Docker-Privileged-blue?logo=docker&logoColor=white)](https://www.docker.com/)
[![Nmap](https://img.shields.io/badge/Nmap-Scanner-004170?logo=gnu-bash&logoColor=white)](https://nmap.org/)
[![Scapy](https://img.shields.io/badge/Scapy-Network-black?logo=linux&logoColor=white)](https://scapy.net/)
[![License](https://img.shields.io/badge/License-MIT-green?logo=opensourceinitiative&logoColor=white)](https://opensource.org/licenses/MIT)

---

**Sentinel-Core AI** es una plataforma de auditoría de ciberseguridad multimodal diseñada para transformar datos técnicos crudos en inteligencia estratégica. Combina motores de escaneo de bajo nivel con IA avanzada para generar diagnósticos de riesgo y reportes ejecutivos en tiempo real.

---

## 🚀 Visión General

A diferencia de los escáneres tradicionales, Sentinel-Core no solo detecta puertos abiertos; analiza la superficie de ataque bajo marcos de cumplimiento como:

- 🔐 [ISO 27001](https://www.iso.org/isoiec-27001-information-security.html)
- 🛡️ [NIST](https://www.nist.gov/cyberframework)

Y traduce los hallazgos técnicos a impacto de negocio.

---

## ✨ Características Principales

### 📡 Escaneo de Precisión (Privileged Engines)

- **Sentinel-Scapy** → Descubrimiento L2 (ARP) con paquetes crudos  
- **Sentinel-Nmap** → Fingerprinting avanzado de servicios  
- **Web-Enum** → Fuzzing y análisis HTTP  

---

### 🧠 Inteligencia Artificial (Cyber-Jarvis Core)

- 🤖 Integración con [Google Gemini](https://aistudio.google.com/)  
- 📊 Análisis multimodal (red + servicios + web)  
- 📄 Generación de reportes ejecutivos en PDF  
- 📚 Soporte para RAG (Knowledge Base)  

---

## 🛠️ Stack Tecnológico

| Componente | Tecnología |
|-----------|----------|
| 🖥️ Frontend | [Streamlit](https://streamlit.io/) |
| 🧠 AI Engine | [Google Gemini 2.5 Flash](https://aistudio.google.com/) |
| 🌐 Network Ops | [Scapy](https://scapy.net/) & [Nmap](https://nmap.org/) |
| 📊 Visualización | Plotly |
| 🐳 Containerización | [Docker](https://www.docker.com/) |

---

## 🐳 Instalación y Despliegue (Quick Start)

### 📌 Requisitos
- Linux (Kali / Ubuntu)
- Docker + Docker Compose
- API Key de [Google AI Studio](https://aistudio.google.com/)

---

### ⚡ Despliegue automático

```bash
git clone https://github.com/diegomty/Hackaton-Sentinel.git
cd Hackaton-Sentinel
chmod +x setup.sh
sudo ./setup.sh
NOTA: En caso de que la Herramienta Scapy pida Permisos una vez que se ha descargado el repositorio ejecutar con el codigo
sudo $(pwd)/venv/bin/python -m streamlit run app.py
````
Desarrollado por:
SpectrumCode Para el Hackaton Troyano 2026

