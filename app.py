import streamlit as st
from streamlit_option_menu import option_menu
from scanners.nmap_engine import run_nmap_scan
from analizador_gemini import (
    analizar_con_ia,
    analizar_auditoria_ia,
    analizar_movimiento_lateral_ia,
    generar_scripts_ia,
)
from scanners.scapy_engine import run_arp_scan, run_passive_sniff, save_baseline, load_baseline, remove_from_baseline, check_baseline, detect_arp_spoofing
from scanners.ssl_analyzer import run_ssl_analysis
from scanners.email_checker import run_email_security_check
import plotly.graph_objects as go
import datetime
import os

# app.py - Al inicio del archivo
from utils.config_manager import load_config

# Cargar configuración guardada al iniciar
if 'config' not in st.session_state:
    st.session_state.config = load_config()
    st.session_state.gemini_key    = st.session_state.config.get("gemini_key", "")
    st.session_state.anthropic_key = st.session_state.config.get("anthropic_key", "")
    st.session_state.ai_provider   = st.session_state.config.get("ai_provider", "gemini")

# Auto-detectar red y dependencias (una sola vez por sesión)
if 'net_iface' not in st.session_state:
    from utils.network_detector import get_active_network, get_setup_guide, get_os
    _iface, _subnet = get_active_network()
    st.session_state.net_iface    = _iface
    st.session_state.net_subnet   = _subnet
    st.session_state.net_os       = get_os()
    st.session_state.setup_issues = get_setup_guide()


# --- FUNCIÓN DE PROCESAMIENTO DE ESTADÍSTICAS ---
def procesar_estadisticas(scan_data, web_data=None):
    total_puertos = 0
    criticos_activos = 0
    en_progreso = 0
    hallazgos = []

    severidad_map = {
        "21": ("Crítico", "#FF4B4B"), "23": ("Crítico", "#FF4B4B"),
        "3389": ("Crítico", "#FF4B4B"), "445": ("Crítico", "#FF4B4B"),
        "3306": ("Crítico", "#FF4B4B"), "5432": ("Crítico", "#FF4B4B"),
        "27017": ("Crítico", "#FF4B4B"), "6379": ("Crítico", "#FF4B4B"),
        "80": ("Medio", "#FFD700"), "8080": ("Medio", "#FFD700"),
        "22": ("Alto", "#FF7F50"), "443": ("Bajo", "#39FF14"),
    }

    for host in scan_data.get("hosts", []):
        for port_info in host.get("ports", []):
            p_id = f"{host['ip']}:{port_info['port']}"
            total_puertos += 1
            p_str = str(port_info["port"])
            sev, color = severidad_map.get(p_str, ("Bajo", "#39FF14"))

            if p_id not in st.session_state.remediadas_ids:
                if sev == "Crítico": criticos_activos += 1
                elif sev in ["Alto", "Medio"]: en_progreso += 1
                hallazgos.append({
                    "id": p_id,
                    "host": host["ip"],
                    "servicio": port_info["service"],
                    "nivel": sev,
                    "color": color,
                    "estado": "Pendiente",
                    "fuente": "nmap",
                })

    # Integrate web scan findings
    web_secrets_count = 0
    web_headers_missing = 0
    if web_data and "error" not in web_data:
        web_secrets_count = web_data.get("total_secrets_found", 0)
        web_headers_missing = len(web_data.get("missing_security_headers", []))

        for sec in web_data.get("js_secrets", []):
            w_id = f"web:js:{sec.get('type','')}:{sec.get('masked','')}"
            if w_id not in st.session_state.remediadas_ids:
                criticos_activos += 1
                hallazgos.append({
                    "id": w_id,
                    "host": web_data.get("target", "Web"),
                    "servicio": f"Secret en JS: {sec.get('type','')} ({sec.get('masked','')})",
                    "nivel": "Crítico",
                    "color": "#FF4B4B",
                    "estado": "Pendiente",
                    "fuente": "web",
                })

        for entry in web_data.get("found_paths", []):
            for sec in entry.get("secrets", []):
                w_id = f"web:path:{entry['path']}:{sec.get('type','')}"
                if w_id not in st.session_state.remediadas_ids:
                    criticos_activos += 1
                    hallazgos.append({
                        "id": w_id,
                        "host": web_data.get("target", "Web"),
                        "servicio": f"Secret en {entry['path']}: {sec.get('type','')}",
                        "nivel": "Crítico",
                        "color": "#FF4B4B",
                        "estado": "Pendiente",
                        "fuente": "web",
                    })

        for issue in web_data.get("cors_issues", []):
            w_id = f"web:cors:{issue.get('type','')}"
            if w_id not in st.session_state.remediadas_ids:
                sev = issue.get("severity", "Medio")
                color = "#FF7F50" if sev == "Alto" else "#FFD700"
                if sev == "Alto": criticos_activos += 1
                else: en_progreso += 1
                hallazgos.append({
                    "id": w_id,
                    "host": web_data.get("target", "Web"),
                    "servicio": f"CORS: {issue.get('type','')}",
                    "nivel": sev,
                    "color": color,
                    "estado": "Pendiente",
                    "fuente": "web",
                })

        if web_data.get("exposed_source_maps"):
            w_id = "web:sourcemaps"
            if w_id not in st.session_state.remediadas_ids:
                en_progreso += 1
                hallazgos.append({
                    "id": w_id,
                    "host": web_data.get("target", "Web"),
                    "servicio": f"Source maps expuestos ({len(web_data['exposed_source_maps'])} archivos)",
                    "nivel": "Alto",
                    "color": "#FF7F50",
                    "estado": "Pendiente",
                    "fuente": "web",
                })

        graphql = web_data.get("graphql", {})
        if graphql.get("exposed"):
            w_id = "web:graphql"
            if w_id not in st.session_state.remediadas_ids:
                en_progreso += 1
                hallazgos.append({
                    "id": w_id,
                    "host": web_data.get("target", "Web"),
                    "servicio": f"GraphQL introspection expuesta en {graphql.get('endpoint','')}",
                    "nivel": "Alto",
                    "color": "#FF7F50",
                    "estado": "Pendiente",
                    "fuente": "web",
                })

    return {
        "totales": total_puertos,
        "criticos": criticos_activos,
        "remediadas": len(st.session_state.remediadas_ids),
        "en_progreso": en_progreso,
        "web_secrets": web_secrets_count,
        "web_headers_missing": web_headers_missing,
        "distribucion": [criticos_activos, en_progreso, 0, max(0, total_puertos - criticos_activos - en_progreso)],
        "lista_hallazgos": hallazgos,
    }

# --- INICIALIZACIÓN DE MEMORIA ---
if 'gemini_key' not in st.session_state:
    st.session_state.gemini_key = ""
if 'anthropic_key' not in st.session_state:
    st.session_state.anthropic_key = ""
if 'ai_provider' not in st.session_state:
    st.session_state.ai_provider = "gemini"

# --- ESTADO DE GESTIÓN (Añadir al inicio con los otros session_state) ---
if 'remediadas_ids' not in st.session_state:
    st.session_state.remediadas_ids = set() # Guardaremos los puertos "solucionados" aquí

# 1. CONFIGURACIÓN DE LA PÁGINA
st.set_page_config(
    page_title="OtsuSearch",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. ESTILO CSS PERSONALIZADO (Look & Feel SOC)
st.markdown("""
    <style>
    /* ── Global ─────────────────────────────────────────────────── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
    .stApp {
        background-color: #080C14;
        color: #E6EDF3;
        font-family: 'Inter', 'Segoe UI', sans-serif;
    }
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0D1117 0%, #0A0E17 100%);
        border-right: 1px solid #21262D;
    }
    .block-container { padding-top: 1.5rem !important; }
    #MainMenu, footer { visibility: hidden; }
    [data-testid="stToolbar"] { display: none; }
    section[data-testid="stSidebar"] > div { padding-top: 1.5rem; }

    /* ── Typography ──────────────────────────────────────────────── */
    h1 {
        color: #E6EDF3 !important;
        font-size: 1.65rem !important;
        font-weight: 700 !important;
        letter-spacing: -0.02em !important;
        margin-bottom: 0.15rem !important;
    }
    h2 { color: #C9D1D9 !important; font-size: 1.2rem !important; font-weight: 600 !important; }
    h3 { color: #00D4FF !important; font-size: 0.85rem !important; font-weight: 700 !important;
         letter-spacing: 0.1em !important; text-transform: uppercase !important; }

    /* ── Metric Cards ────────────────────────────────────────────── */
    .metric-card {
        background: #10151E;
        border: 1px solid #1E2733;
        border-radius: 10px;
        padding: 1rem 1.2rem 0.9rem;
        position: relative;
        overflow: hidden;
        min-height: 90px;
        transition: border-color 0.2s;
    }
    .metric-card:hover { border-color: #2D3748; }
    .metric-card .accent-bar {
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 3px;
        background: linear-gradient(90deg, #00D4FF, #0077FF);
        border-radius: 10px 10px 0 0;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 800;
        margin: 0.2rem 0 0;
        line-height: 1;
        color: #E6EDF3;
        letter-spacing: -0.03em;
    }
    .metric-title {
        color: #4A5568;
        font-size: 0.65rem;
        letter-spacing: 0.12rem;
        text-transform: uppercase;
        font-weight: 600;
        margin-bottom: 0.1rem;
    }
    .metric-sub { color: #4A5568; font-size: 0.72rem; margin-top: 0.35rem; }

    /* ── Status Banner ───────────────────────────────────────────── */
    .status-live {
        background: #13080C;
        border: 1px solid #FF4B4B44;
        border-left: 4px solid #FF4B4B;
        border-radius: 8px;
        padding: 9px 14px;
        margin-bottom: 18px;
        font-size: 0.82rem;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .status-idle {
        background: #10151E;
        border: 1px solid #2D3748;
        border-left: 4px solid #4A5568;
        border-radius: 8px;
        padding: 9px 14px;
        margin-bottom: 18px;
        font-size: 0.82rem;
    }

    /* ── Scanner Summary Cards ───────────────────────────────────── */
    .scanner-card {
        background: #10151E;
        border: 1px solid #1E2733;
        border-radius: 8px;
        padding: 11px 13px;
        height: 100%;
        font-size: 0.82rem;
    }

    /* ── Finding Rows ────────────────────────────────────────────── */
    .finding-row {
        background: #10151E;
        border: 1px solid #1E2733;
        border-radius: 6px;
        padding: 10px 13px;
        margin-bottom: 5px;
        font-size: 0.83rem;
    }

    /* ── Sidebar nav override ────────────────────────────────────── */
    [data-testid="stSidebar"] hr { border-color: #21262D; margin: 0.6rem 0; }
    </style>
    """, unsafe_allow_html=True)

# 3. BARRA LATERAL (SideBar)
with st.sidebar:
    st.markdown("""
        <div style='text-align:center; padding: 8px 0 12px;'>
            <p style='font-size:22px; font-weight:800; color:#E6EDF3; margin:0; letter-spacing:1px;'>
                Otsu<span style='color:#00D4FF;'>Search</span>
            </p>
            <p style='font-size:10px; color:#4A5568; letter-spacing:3px; text-transform:uppercase; margin:4px 0 0;'>
                Cyber Audit Platform
            </p>
        </div>
    """, unsafe_allow_html=True)

    selected = option_menu(
        menu_title=None,
        options=["Dashboard", "Scanners", "Knowledge Base", "Reports", "Settings"],
        icons=["speedometer2", "shield-lock", "book", "file-earmark-bar-graph", "gear"],
        default_index=0,
        styles={
            "container": {"background-color": "transparent", "padding": "0"},
            "icon": {"color": "#00D4FF", "font-size": "16px"},
            "nav-link": {
                "font-size": "14px", "text-align": "left", "color": "#8B949E",
                "padding": "9px 16px", "border-radius": "6px", "margin": "1px 0",
            },
            "nav-link-selected": {
                "background-color": "#161B22", "color": "#E6EDF3",
                "border-left": "3px solid #00D4FF", "font-weight": "600",
            },
        }
    )

    st.markdown("<hr style='border-color:#1E2733;margin:12px 0;'>", unsafe_allow_html=True)

    # Indicador de Motor IA
    _active_key = (st.session_state.anthropic_key if st.session_state.ai_provider == "claude"
                   else st.session_state.gemini_key)
    _ia_ok = bool(_active_key.strip())
    _provider_label = "Claude" if st.session_state.ai_provider == "claude" else "Gemini"
    _dot_color  = "#39FF14" if _ia_ok else "#FF4B4B"
    _ia_text    = f"{_provider_label} — Activo" if _ia_ok else "Sin API Key"
    st.markdown(f"""
        <div style='padding:9px 12px; border-radius:8px; background:#10151E;
                    border:1px solid {"#39FF1433" if _ia_ok else "#FF4B4B33"};
                    display:flex; align-items:center; gap:8px;'>
            <span style='color:{_dot_color}; font-size:10px;'>●</span>
            <span style='color:#8B949E; font-size:12px; font-weight:500;'>Motor IA</span>
            <span style='color:{_dot_color}; font-size:12px; font-weight:600; margin-left:auto;'>{_ia_text}</span>
        </div>
    """, unsafe_allow_html=True)

    # Indicador de red detectada
    _net_color = "#39FF14" if st.session_state.net_subnet != "192.168.1.0/24" else "#4A5568"
    st.markdown(f"""
        <div style='margin-top:6px; padding:9px 12px; border-radius:8px; background:#10151E;
                    border:1px solid #1E2733; display:flex; align-items:center; gap:8px;'>
            <span style='color:{_net_color}; font-size:10px;'>●</span>
            <span style='color:#8B949E; font-size:12px; font-weight:500;'>Red detectada</span>
            <span style='color:#C9D1D9; font-size:11px; font-weight:600; margin-left:auto;'>
                {st.session_state.net_subnet}
            </span>
        </div>
    """, unsafe_allow_html=True)

    # Alertas de setup (dependencias faltantes)
    if st.session_state.get('setup_issues'):
        st.markdown("<hr style='border-color:#1E2733;margin:10px 0;'>", unsafe_allow_html=True)
        st.markdown("<p style='color:#FFD700;font-size:11px;font-weight:600;margin:0 0 6px;'>⚠ Setup pendiente</p>", unsafe_allow_html=True)
        for key, issue in st.session_state.setup_issues.items():
            st.markdown(f"<p style='color:#FF4B4B;font-size:10px;margin:2px 0;'>● {issue['title']}</p>", unsafe_allow_html=True)

# ─── TOPOLOGÍA DE RED ────────────────────────────────────────────────────────
def _render_network_graph(arp_data, nmap_data=None):
    from streamlit_echarts import st_echarts

    CRITICAL_PORTS = {21, 23, 445, 3306, 5432, 1433, 3389, 4444, 5900, 6379, 27017}
    HIGH_PORTS = {22, 80, 8080, 8443, 443, 8000, 8888}

    risk_map = {}
    if nmap_data:
        for host in nmap_data.get('hosts', []):
            ip = host['ip']
            ports = [p['port'] for p in host.get('ports', [])]
            services = [f"{p['port']}/{p.get('service', '?')}" for p in host.get('ports', [])]
            if any(p in CRITICAL_PORTS for p in ports):
                risk_map[ip] = ('critical', services)
            elif any(p in HIGH_PORTS for p in ports):
                risk_map[ip] = ('high', services)
            else:
                risk_map[ip] = ('medium', services)

    devices = arp_data.get('devices', [])
    if not devices:
        st.info("Sin dispositivos para visualizar.")
        return

    nodes = [{
        "id": "NET",
        "name": "RED LOCAL",
        "symbolSize": 55,
        "symbol": "roundRect",
        "itemStyle": {
            "color": "#161B22", "borderColor": "#00D4FF", "borderWidth": 2,
            "shadowBlur": 18, "shadowColor": "#00D4FF",
        },
        "label": {"show": True, "color": "#00D4FF", "fontWeight": "bold", "fontSize": 10},
        "fixed": True, "x": 0, "y": 0,
    }]
    links = []

    for device in devices:
        ip = device['ip']
        mac = device.get('mac', 'N/A')
        risk, services = risk_map.get(ip, ('unknown', []))

        color  = {"critical": "#FF3B3B", "high": "#FFB800", "medium": "#00E676"}.get(risk, "#8B949E")
        shadow = {"critical": 28,        "high": 14,        "medium": 8       }.get(risk, 0)
        size   = {"critical": 44,        "high": 38,        "medium": 32      }.get(risk, 30)

        svc_str = ", ".join(services[:4]) + ("…" if len(services) > 4 else "") if services else "Sin escaneo Nmap"
        tip = (
            f"<b style='color:{color}'>{ip}</b><br/>"
            f"MAC: {mac}<br/>"
            f"Servicios: {svc_str}"
            + ("<br/><b style='color:#FF3B3B'>⚠ PUERTOS CRÍTICOS</b>" if risk == 'critical' else "")
        )

        nodes.append({
            "id": ip, "name": ip,
            "symbolSize": size,
            "itemStyle": {"color": color, "shadowBlur": shadow, "shadowColor": color,
                          "borderColor": color, "borderWidth": 1},
            "label": {"show": True, "color": "#E6EDF3", "fontSize": 9},
            "tooltip": {"formatter": tip},
        })
        links.append({
            "source": "NET", "target": ip,
            "lineStyle": {
                "color": "#FF3B3B" if risk == 'critical' else "#21262D",
                "width": 2.5 if risk == 'critical' else 1,
            },
        })

    option = {
        "backgroundColor": "#0D1117",
        "tooltip": {"trigger": "item"},
        "series": [{
            "type": "graph",
            "layout": "force",
            "animation": True,
            "animationDuration": 1200,
            "data": nodes,
            "links": links,
            "roam": True,
            "draggable": True,
            "force": {"repulsion": 300, "edgeLength": [130, 220], "gravity": 0.08,
                      "layoutAnimation": True},
            "lineStyle": {"color": "#21262D", "width": 1, "curveness": 0.15},
            "emphasis": {"focus": "adjacency",
                         "lineStyle": {"width": 3, "color": "#00D4FF"}},
            "label": {"position": "bottom"},
        }],
    }
    st_echarts(options=option, height="480px", key="network_topology")


# 4. LÓGICA DE NAVEGACIÓN
fecha_actual = datetime.datetime.now().strftime("%A, %d de %B de %Y")

if selected == "Dashboard":
    st.title("Centro de Operaciones")

    has_nmap = 'last_scan' in st.session_state
    has_arp  = 'last_arp'  in st.session_state
    has_web  = 'last_web'  in st.session_state

    if has_nmap or has_web:
        stats = procesar_estadisticas(
            st.session_state.get('last_scan', {"hosts": []}),
            st.session_state.get('last_web'),
        )
        sources = " · ".join(filter(None, [
            "Nmap" if has_nmap else "",
            "Scapy" if has_arp else "",
            "Web" if has_web else "",
        ]))
        st.markdown(f"""
            <div class='status-live'>
                <span style='color:#FF4B4B; font-size:9px;'>●</span>
                <span style='color:#C9D1D9; font-weight:600;'>DATOS EN VIVO</span>
                <span style='color:#4A5568;'>·</span>
                <span style='color:#8B949E;'>{sources}</span>
                <span style='color:#4A5568; margin-left:auto; font-size:0.75rem;'>{fecha_actual}</span>
            </div>
        """, unsafe_allow_html=True)
    else:
        stats = {
            "totales": 0, "criticos": 0, "remediadas": 0, "en_progreso": 0,
            "web_secrets": 0, "web_headers_missing": 0,
            "distribucion": [0, 0, 0, 0], "lista_hallazgos": [],
        }
        st.markdown(f"""
            <div class='status-idle'>
                <span style='color:#4A5568;'>○</span>
                <span style='color:#4A5568; margin-left:6px;'>Modo espera — ejecuta un escaneo para ver datos</span>
                <span style='color:#4A5568; float:right; font-size:0.75rem;'>{fecha_actual}</span>
            </div>
        """, unsafe_allow_html=True)

    # ── FILA 1: KPIs principales ─────────────────────────────────────────────
    hosts_count = st.session_state['last_arp']['hosts_found'] if has_arp else 0
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.markdown(f"""<div class='metric-card'>
            <div class='accent-bar' style='background:linear-gradient(90deg,#00D4FF,#0077FF);'></div>
            <p class='metric-title'>Hosts detectados</p>
            <p class='metric-value' style='color:#00D4FF;'>{hosts_count}</p>
            <p class='metric-sub'>ARP · Scapy</p>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown(f"""<div class='metric-card'>
            <div class='accent-bar' style='background:linear-gradient(90deg,#FF4B4B,#FF0055);'></div>
            <p class='metric-title'>Críticas</p>
            <p class='metric-value' style='color:#FF4B4B;'>{stats['criticos']}</p>
            <p class='metric-sub'>Puertos + Web</p>
        </div>""", unsafe_allow_html=True)
    with col3:
        st.markdown(f"""<div class='metric-card'>
            <div class='accent-bar' style='background:linear-gradient(90deg,#FF7F50,#FF4500);'></div>
            <p class='metric-title'>En progreso</p>
            <p class='metric-value' style='color:#FF7F50;'>{stats['en_progreso']}</p>
            <p class='metric-sub'>Alto · Medio</p>
        </div>""", unsafe_allow_html=True)
    with col4:
        st.markdown(f"""<div class='metric-card'>
            <div class='accent-bar' style='background:linear-gradient(90deg,#FFD700,#FF8800);'></div>
            <p class='metric-title'>Secretos web</p>
            <p class='metric-value' style='color:#FFD700;'>{stats['web_secrets']}</p>
            <p class='metric-sub'>API keys expuestas</p>
        </div>""", unsafe_allow_html=True)
    with col5:
        st.markdown(f"""<div class='metric-card'>
            <div class='accent-bar' style='background:linear-gradient(90deg,#39FF14,#00D4AA);'></div>
            <p class='metric-title'>Remediadas</p>
            <p class='metric-value' style='color:#39FF14;'>{stats['remediadas']}</p>
            <p class='metric-sub'>Gestionadas</p>
        </div>""", unsafe_allow_html=True)

    # ── FILA 2: Resumen rápido por scanner ──────────────────────────────────
    st.markdown("<div style='margin-top:18px;margin-bottom:6px;'></div>", unsafe_allow_html=True)
    r1, r2, r3, r4 = st.columns(4)
    with r1:
        if has_nmap:
            scan = st.session_state['last_scan']
            n_hosts = len(scan.get('hosts', []))
            n_ports = sum(len(h.get('ports', [])) for h in scan.get('hosts', []))
            st.markdown(f"""<div class='scanner-card' style='border-left:3px solid #00D4FF;'>
                <span style='color:#00D4FF;font-weight:700;font-size:12px;'>🌐 NMAP</span><br>
                <span style='color:#C9D1D9;'>{scan.get('target','')}</span><br>
                <span style='color:#4A5568;font-size:11px;'>{n_hosts} host · {n_ports} puertos</span>
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown("<div class='scanner-card'><span style='color:#4A5568;font-size:12px;'>🌐 Nmap — sin datos</span></div>", unsafe_allow_html=True)
    with r2:
        if has_arp:
            arp = st.session_state['last_arp']
            st.markdown(f"""<div class='scanner-card' style='border-left:3px solid #39FF14;'>
                <span style='color:#39FF14;font-weight:700;font-size:12px;'>📡 SCAPY</span><br>
                <span style='color:#C9D1D9;'>{arp.get('hosts_found',0)} dispositivos</span><br>
                <span style='color:#4A5568;font-size:11px;'>Modo: {arp.get('mode','?')}</span>
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown("<div class='scanner-card'><span style='color:#4A5568;font-size:12px;'>📡 Scapy — sin datos</span></div>", unsafe_allow_html=True)
    with r3:
        if has_web:
            w = st.session_state['last_web']
            n_paths = len(w.get('found_paths', []))
            n_sec   = w.get('total_secrets_found', 0)
            st.markdown(f"""<div class='scanner-card' style='border-left:3px solid #FF7F50;'>
                <span style='color:#FF7F50;font-weight:700;font-size:12px;'>🕸️ WEB</span><br>
                <span style='color:#C9D1D9;'>{w.get('target','')}</span><br>
                <span style='color:#4A5568;font-size:11px;'>{n_paths} rutas · {n_sec} secretos</span>
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown("<div class='scanner-card'><span style='color:#4A5568;font-size:12px;'>🕸️ Web — sin datos</span></div>", unsafe_allow_html=True)
    with r4:
        ssl_ok  = 'last_ssl'   in st.session_state
        mail_ok = 'last_email' in st.session_state
        ssl_f   = len(st.session_state.get('last_ssl',  {}).get('findings', [])) if ssl_ok  else 0
        mail_f  = len(st.session_state.get('last_email',{}).get('findings', [])) if mail_ok else 0
        c4_color = "#A855F7" if (ssl_ok or mail_ok) else "#4A5568"
        c4_label = f"SSL: {ssl_f} hallazgos · Email: {mail_f} hallazgos" if (ssl_ok or mail_ok) else "sin datos"
        st.markdown(f"""<div class='scanner-card' style='border-left:3px solid {c4_color};'>
            <span style='color:{c4_color};font-weight:700;font-size:12px;'>🔐 SSL · EMAIL</span><br>
            <span style='color:#4A5568;font-size:11px;'>{c4_label}</span>
        </div>""", unsafe_allow_html=True)

    # ── FILA 3: Gráficas ────────────────────────────────────────────────────
    st.markdown("<div style='margin-top:22px;'></div>", unsafe_allow_html=True)
    c_left, c_right = st.columns([1, 2])
    with c_left:
        st.markdown("### Distribución de riesgo")
        if sum(stats['distribucion']) > 0:
            fig = go.Figure(data=[go.Pie(
                labels=['Crítico', 'Alto', 'Medio', 'Bajo'],
                values=stats['distribucion'],
                hole=.65,
                marker_colors=['#FF4B4B', '#FF7F50', '#FFD700', '#39FF14'],
                textinfo='none',
            )])
        else:
            fig = go.Figure(data=[go.Pie(
                labels=['Sin datos'], values=[1], hole=.65,
                marker_colors=['#1E2733'], textinfo='none',
            )])
        fig.update_layout(
            showlegend=True,
            legend=dict(font=dict(color="#8B949E", size=11), orientation="h", x=0, y=-0.1),
            paper_bgcolor='rgba(0,0,0,0)',
            height=270,
            margin=dict(l=0, r=0, t=10, b=0),
            font=dict(color="#8B949E"),
        )
        st.plotly_chart(fig, use_container_width=True)

    with c_right:
        st.markdown("### Hallazgos por categoría")
        if has_nmap or has_web:
            nmap_ports = stats['totales']
            web_secs   = stats['web_secrets']
            cors_n     = len(st.session_state.get('last_web', {}).get('cors_issues', []))
            missing_h  = stats['web_headers_missing']
            maps_n     = len(st.session_state.get('last_web', {}).get('exposed_source_maps', []))

            bar_labels = ['Puertos', 'Secretos JS', 'CORS', 'Headers', 'Source Maps']
            bar_values = [nmap_ports, web_secs, cors_n, missing_h, maps_n]
            bar_colors = ['#00D4FF', '#FF4B4B', '#FF7F50', '#FFD700', '#A855F7']

            fig_b = go.Figure(data=[go.Bar(
                x=bar_labels, y=bar_values,
                marker_color=bar_colors,
                marker_line_width=0,
                opacity=0.9,
                text=bar_values,
                textposition='outside',
                textfont=dict(color="#8B949E", size=11),
            )])
            fig_b.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                height=270, margin=dict(l=0, r=0, t=10, b=0),
                font=dict(color="#8B949E", size=11),
                xaxis=dict(showgrid=False, color="#4A5568"),
                yaxis=dict(showgrid=True, gridcolor='#1E2733', zeroline=False, color="#4A5568"),
            )
            st.plotly_chart(fig_b, use_container_width=True)
        else:
            st.markdown("""
                <div style='height:270px;display:flex;align-items:center;justify-content:center;
                            background:#10151E;border:1px solid #1E2733;border-radius:8px;'>
                    <span style='color:#4A5568;font-size:13px;'>Ejecuta un escaneo para ver datos</span>
                </div>
            """, unsafe_allow_html=True)

    # ── FILA 4: Gestión de hallazgos ────────────────────────────────────────
    st.markdown("<hr style='border-color:#1E2733;margin:24px 0 16px;'>", unsafe_allow_html=True)
    st.markdown("### Hallazgos activos")

    if stats['lista_hallazgos']:
        for h in stats['lista_hallazgos']:
            fuente_icon = {"nmap": "🌐", "web": "🕸️"}.get(h.get('fuente', ''), "🔍")
            col_info, col_btn = st.columns([5, 1])
            with col_info:
                st.markdown(f"""
                    <div class='finding-row' style='border-left:4px solid {h["color"]};'>
                        <span style='color:{h["color"]};font-weight:700;font-size:12px;
                                     text-transform:uppercase;letter-spacing:0.05em;'>{h["nivel"]}</span>
                        <span style='color:#4A5568;font-size:11px;margin-left:8px;'>{fuente_icon}</span>
                        <span style='color:#4A5568;margin:0 6px;'>·</span>
                        <span style='color:#C9D1D9;'>{h["host"]}</span>
                        <span style='color:#4A5568;margin:0 6px;'>·</span>
                        <span style='color:#8B949E;'>{h["servicio"]}</span>
                    </div>
                """, unsafe_allow_html=True)
            with col_btn:
                if st.button("Cerrar", key=f"btn_{h['id']}", type="secondary"):
                    st.session_state.remediadas_ids.add(h['id'])
                    st.rerun()
    else:
        st.success("Sin hallazgos pendientes.")

elif selected == "Scanners":
    st.title("Scanners")
    t_nmap, t_scapy, t_web, t_ssl, t_email = st.tabs([
        "🌐 Nmap", "📡 Red (Scapy)", "🕸️ Web", "🔐 SSL/TLS", "📧 Email"
    ])
    
    with t_nmap:
        col_conf, col_term = st.columns([1, 2])

        with col_conf:
            st.markdown("### CONFIGURACIÓN — Nmap")
            target = st.text_input("Objetivo (IP / Hostname)", "127.0.0.1", key="nmap_t")
            perfil = st.selectbox(
                "Perfil",
                ["Rápido (Top 100)", "Agresivo (Full Scan)", "Sigiloso (SYN Scan)", "Completo (All Ports)"],
                key="nmap_p",
            )

            st.write("---")
            st.markdown("##### Módulos Avanzados")
            nse_on  = st.toggle("🔗 NSE Script Chaining",   value=False, help="Ejecuta scripts NSE específicos según los puertos detectados")
            cve_on  = st.toggle("🔍 CVE Lookup (NVD API)",  value=False, help="Consulta el NIST NVD en tiempo real para cada servicio")
            ids_on  = st.toggle("🛡️ Detección IDS/WAF",     value=False, help="Probes TCP anómalos (Null/FIN/Xmas) para detectar firewalls")
            st.write("")
            zombie_host = st.text_input(
                "🧟 Idle Scan — IP Zombie (opcional)",
                placeholder="ej: 192.168.1.50",
                help="Si se especifica, usa esta IP como intermediario (máximo sigilo)"
            )

            if st.button("🚀 Iniciar Auditoría Completa", width='stretch', type="primary"):
                lista_negra = st.session_state.config.get("excluded_ips", "").replace(" ", "").split(",")
                if target in lista_negra:
                    st.error(f"❌ ACCESO DENEGADO: {target} está en la lista de exclusión.")
                    st.info("Modifica la lista en Settings > Red.")
                else:
                    with st.status("Ejecutando escaneo...", expanded=True) as status:
                        st.caption("Consola en vivo:")
                        _nmap_console = st.empty()
                        _nmap_logs = []
                        def _nmap_log(msg):
                            _nmap_logs.append(msg)
                            _nmap_console.code("\n".join(_nmap_logs[-60:]), language="bash")

                        resultado_nmap = run_nmap_scan(
                            target, perfil,
                            log_fn=_nmap_log,
                            enable_nse=nse_on,
                            enable_cve=cve_on,
                            enable_ids=ids_on,
                            zombie_host=zombie_host,
                        )

                        if "error" in resultado_nmap:
                            st.error(f"Fallo en Nmap: {resultado_nmap['error']}")
                            status.update(label="❌ Error", state="error")
                        else:
                            st.write("🤖 Analizando con IA...")
                            reporte_ia = analizar_con_ia(
                                resultado_nmap,
                                provider=st.session_state.ai_provider,
                                gemini_key=st.session_state.gemini_key,
                                anthropic_key=st.session_state.anthropic_key,
                            )
                            st.session_state['last_scan']   = resultado_nmap
                            st.session_state['last_report'] = reporte_ia
                            st.session_state.pop('lateral_movement', None)
                            status.update(label="✅ Auditoría Finalizada", state="complete", expanded=False)
                            st.success("Análisis completado.")

        with col_term:
            st.markdown("### Terminal & Reporte IA")

            if 'last_scan' in st.session_state:
                res = st.session_state['last_scan']

                t_raw, t_ai, t_nse, t_cve, t_ids, t_lateral, t_fix = st.tabs([
                    "💻 Técnico", "🤖 IA Audit", "🔗 NSE", "🔍 CVE Intel",
                    "🛡️ IDS/WAF", "🎯 Mov. Lateral", "🔧 Fix-it",
                ])

                # ── Tab: Salida técnica ──────────────────────────────────────
                with t_raw:
                    output = f"[+] Modo: {res.get('mode','')}\n[+] Objetivo: {res['target']}\n[+] Timestamp: {res['timestamp']}\n"
                    for h in res['hosts']:
                        output += f"\nHost: {h['ip']} ({h['hostname']}) | OS: {h['os_detected']}\n"
                        for p in h['ports']:
                            cve_count = len(p.get('cves', []))
                            cve_tag = f" [{cve_count} CVE(s)]" if cve_count else ""
                            output += f"  [{p['state']}] {p['port']}/{p['service']} — {p['product']} {p['version']}{cve_tag}\n".rstrip() + "\n"
                    st.code(output, language="bash")

                # ── Tab: Análisis IA ─────────────────────────────────────────
                with t_ai:
                    st.markdown(st.session_state.get('last_report', ''))
                    if st.button("📄 Generar Reporte PDF Corporativo", key="btn_pdf_nmap"):
                        from utils.pdf_generator import generar_reporte_final
                        with st.spinner("Compilando PDF..."):
                            ruta_pdf = generar_reporte_final(
                                scan_nmap=res, scan_scapy=None, scan_web=None,
                                ai_analysis=st.session_state['last_report'],
                            )
                            with open(ruta_pdf, "rb") as f:
                                st.download_button(
                                    "💾 Descargar PDF",
                                    data=f,
                                    file_name=f"OtsuSearch_{res['target']}.pdf",
                                    mime="application/pdf",
                                )

                # ── Tab: NSE Results ─────────────────────────────────────────
                with t_nse:
                    nse_results = res.get('nse_results', [])
                    if not nse_results:
                        st.info("NSE Script Chaining no fue habilitado o no se encontraron resultados.")
                    else:
                        st.markdown(f"**{len(nse_results)} ejecución(es) NSE completadas**")
                        ALERT_KW = ["VULNERABLE", "eternalblue", "ms17-010", "ms08-067", "anonymous", "empty password"]
                        for nse in nse_results:
                            for script_name, output in nse.get('scripts', {}).items():
                                is_critical = any(kw.lower() in output.lower() for kw in ALERT_KW)
                                border = "#FF4B4B" if is_critical else "#00E5FF"
                                label  = "🚨 CRÍTICO" if is_critical else "ℹ️ Info"
                                with st.expander(f"[{label}] Puerto {nse['port']} — {script_name} ({nse.get('host','')})"):
                                    st.code(output[:3000], language="text")

                # ── Tab: CVE Intelligence ────────────────────────────────────
                with t_cve:
                    cve_findings = res.get('cve_findings', [])
                    if not cve_findings:
                        st.info("CVE Lookup no fue habilitado o no se detectaron versiones de productos.")
                    else:
                        total_cves = sum(len(f['cves']) for f in cve_findings)
                        critical_cves = sum(1 for f in cve_findings for c in f['cves'] if c.get('cvss', 0) >= 9.0)
                        mc1, mc2 = st.columns(2)
                        mc1.metric("CVEs encontrados", total_cves)
                        mc2.metric("Críticos (CVSS ≥ 9.0)", critical_cves)
                        st.write("")
                        for finding in cve_findings:
                            st.markdown(f"**Puerto {finding['port']} — `{finding['product']}`**")
                            for cve in finding['cves']:
                                sev_colors = {"CRITICAL": "#FF4B4B", "HIGH": "#FF7F50", "MEDIUM": "#FFD700", "LOW": "#39FF14"}
                                sev_color  = sev_colors.get(cve.get('severity', '').upper(), "#8B949E")
                                # Priority formula display
                                priority = cve.get('priority', 0)
                                st.markdown(f"""
                                    <div style="background:#161B22;border-left:4px solid {sev_color};padding:10px;border-radius:4px;margin-bottom:6px;">
                                        <b style="color:{sev_color};">{cve['cve_id']}</b>
                                        <span style="color:#8B949E;font-size:11px;margin-left:10px;">
                                            CVSS {cve['cvss']} | Severidad: {cve.get('severity','N/A')} | Prioridad: <b style="color:#00D4FF;">{priority}</b>
                                        </span><br>
                                        <small style="color:#C9D1D9;">{cve['description'][:200]}...</small><br>
                                        <small>
                                            <a href="{cve['nvd_url']}" target="_blank" style="color:#00E5FF;">📖 NVD</a>
                                            &nbsp;|&nbsp;
                                            <a href="{cve['exploitdb_url']}" target="_blank" style="color:#FF7F50;">💥 Exploit-DB</a>
                                        </small>
                                    </div>
                                """, unsafe_allow_html=True)
                            st.write("")

                # ── Tab: IDS/WAF Detection ───────────────────────────────────
                with t_ids:
                    ids = res.get('ids_waf', {})
                    if not ids:
                        st.info("Detección IDS/WAF no fue habilitada en este escaneo.")
                    else:
                        fw  = ids.get('firewall_detected', False)
                        waf = ids.get('ips_waf_suspected', False)
                        dc1, dc2 = st.columns(2)
                        dc1.metric("Firewall Restrictivo", "SÍ 🛡️" if fw  else "NO ✓")
                        dc2.metric("IPS/WAF Sospechado",  "SÍ ⚠️" if waf else "NO ✓")
                        st.write("")
                        probes = ids.get('probe_responses', {})
                        if probes:
                            st.markdown("**Respuestas por tipo de probe:**")
                            for probe_name, result in probes.items():
                                color = {"filtered": "#FF4B4B", "open": "#39FF14", "closed": "#FFD700"}.get(result, "#8B949E")
                                st.markdown(f"- TCP **{probe_name}**: <span style='color:{color};font-weight:bold;'>{result}</span>", unsafe_allow_html=True)
                        evasion = ids.get('evasion_recommendation', '')
                        if evasion:
                            st.write("")
                            st.markdown("**💡 Recomendación de evasión:**")
                            st.code(evasion, language="bash")

                # ── Tab: Movimiento Lateral ──────────────────────────────────
                with t_lateral:
                    if st.button("🎯 Proyectar Movimiento Lateral con IA", type="primary", key="btn_lateral"):
                        with st.spinner("Simulando ruta de ataque APT..."):
                            ml_result = analizar_movimiento_lateral_ia(
                                st.session_state['last_scan'],
                                provider=st.session_state.ai_provider,
                                gemini_key=st.session_state.gemini_key,
                                anthropic_key=st.session_state.anthropic_key,
                            )
                            st.session_state['lateral_movement'] = ml_result

                    if 'lateral_movement' in st.session_state:
                        ml = st.session_state['lateral_movement']
                        st.markdown(ml.get('markdown', ''))

                        pasos = ml.get('pasos', [])
                        if pasos:
                            st.write("---")
                            st.markdown("#### Diagrama de Infiltración")
                            # Build ECharts graph
                            nodes, links = [], []
                            node_ids = set()
                            prob_colors = lambda p: "#FF4B4B" if p >= 75 else "#FF7F50" if p >= 50 else "#FFD700"
                            for step in pasos:
                                desde = step.get('desde', '?')
                                hacia = step.get('hacia', '?')
                                via   = step.get('via', '')
                                prob  = step.get('probabilidad', 50)
                                for nid in [desde, hacia]:
                                    if nid not in node_ids:
                                        node_ids.add(nid)
                                        color = "#FF4B4B" if nid == "Atacante externo" else prob_colors(prob)
                                        nodes.append({"id": nid, "name": nid, "symbolSize": 38,
                                                      "itemStyle": {"color": color},
                                                      "label": {"show": True, "color": "#E6EDF3", "fontSize": 9}})
                                links.append({"source": desde, "target": hacia,
                                              "label": {"show": True, "formatter": f"{prob}%", "color": "#FFD700", "fontSize": 9},
                                              "lineStyle": {"color": prob_colors(prob), "width": 2, "curveness": 0.2}})
                            from streamlit_echarts import st_echarts
                            ml_option = {
                                "backgroundColor": "#0D1117",
                                "tooltip": {"trigger": "item"},
                                "series": [{
                                    "type": "graph", "layout": "force",
                                    "data": nodes, "links": links,
                                    "roam": True, "draggable": True,
                                    "force": {"repulsion": 250, "edgeLength": [150, 250], "gravity": 0.06},
                                    "edgeLabel": {"show": True},
                                    "emphasis": {"focus": "adjacency"},
                                }],
                            }
                            st_echarts(options=ml_option, height="400px", key="lateral_graph")

                            st.write("---")
                            st.markdown("**Pasos de infiltración proyectados:**")
                            for step in pasos:
                                prob = step.get('probabilidad', 0)
                                pcolor = prob_colors(prob)
                                st.markdown(f"""
                                    <div style="background:#161B22;border-left:4px solid {pcolor};padding:10px;border-radius:4px;margin-bottom:5px;">
                                        <b style="color:#00E5FF;">Paso {step.get('paso','?')}</b>
                                        <span style="color:{pcolor};margin-left:10px;font-weight:bold;">{prob}% prob.</span><br>
                                        <small style="color:#8B949E;">
                                            {step.get('desde','?')} → <b style="color:white;">{step.get('hacia','?')}</b><br>
                                            Vía: {step.get('via','?')}<br>
                                            Técnica: <code style="color:#A855F7;">{step.get('tecnica','?')}</code>
                                        </small>
                                    </div>
                                """, unsafe_allow_html=True)
                    else:
                        st.info("Presiona el botón para proyectar cómo un atacante se movería por la red basándose en los servicios detectados.")

                # ── Tab: Fix-it Engine ───────────────────────────────────────
                with t_fix:
                    st.markdown("#### Fix-it Engine — Scripts de Remediación Automática")
                    if st.button("⚡ Generar Scripts de Remediación", type="primary", key="btn_fixengine"):
                        with st.spinner("Generando scripts de remediación..."):
                            scripts = generar_scripts_ia(
                                st.session_state['last_scan'],
                                provider=st.session_state.ai_provider,
                                gemini_key=st.session_state.gemini_key,
                                anthropic_key=st.session_state.anthropic_key,
                            )
                            st.session_state['remediation_scripts'] = scripts
                    if 'remediation_scripts' in st.session_state:
                        st.markdown(st.session_state['remediation_scripts'])
                    else:
                        st.info("Presiona el botón para generar scripts Bash/PowerShell para cada servicio detectado.")
            else:
                st.info("Configura el objetivo y presiona 'Iniciar Auditoría' para ver los resultados aquí.")

    with t_scapy:
        st.subheader("📡 Reconocimiento de Red — ARP & Scapy")

        # ── GUÍA DE SETUP (si hay dependencias faltantes) ────────────────────
        issues = st.session_state.get('setup_issues', {})
        if issues:
            with st.expander("⚠️ Dependencias faltantes — expande para ver cómo resolverlas", expanded=True):
                for key, issue in issues.items():
                    st.markdown(f"""
                        <div style='background:#1A0F00;border-left:4px solid #FFD700;
                                    padding:10px 14px;border-radius:6px;margin-bottom:8px;'>
                            <b style='color:#FFD700;'>{issue["title"]}</b><br>
                            <small style='color:#8B949E;'>{issue["detail"]}</small><br>
                            <code style='color:#00D4FF;font-size:12px;'>{issue["fix"]}</code>
                        </div>
                    """, unsafe_allow_html=True)

        # ── PANEL DE CONTROL ─────────────────────────────────────────────────
        ctrl_col, map_col = st.columns([1, 2])

        with ctrl_col:
            # Usar subred auto-detectada como default, config como override guardado
            _default_range = (
                st.session_state.config.get("default_range")
                or st.session_state.net_subnet
                or "192.168.1.0/24"
            )
            # Mostrar la interfaz detectada como hint
            _detected_iface = st.session_state.net_iface or "auto"
            st.markdown(f"""
                <div style='background:#10151E;border:1px solid #1E2733;border-left:3px solid #00D4FF;
                            padding:8px 12px;border-radius:6px;margin-bottom:10px;font-size:12px;'>
                    <span style='color:#4A5568;'>Red detectada: </span>
                    <span style='color:#00D4FF;font-weight:600;'>{st.session_state.net_subnet}</span>
                    &nbsp;·&nbsp;
                    <span style='color:#4A5568;'>Interfaz: </span>
                    <span style='color:#8B949E;'>{_detected_iface}</span>
                    &nbsp;·&nbsp;
                    <span style='color:#4A5568;'>OS: </span>
                    <span style='color:#8B949E;'>{st.session_state.net_os}</span>
                </div>
            """, unsafe_allow_html=True)

            target_net  = st.text_input("Rango de Red", _default_range)
            scan_mode   = st.radio("Modo de Escaneo", ["Activo (ARP Broadcast)", "Pasivo (Sniff silencioso)"], horizontal=True)
            passive_dur = 30
            if "Pasivo" in scan_mode:
                passive_dur = st.slider("Duración (segundos)", 10, 120, 30)
                st.caption("Zero-packet discovery: escucha tráfico ARP sin enviar nada.")

            with st.expander("Opciones avanzadas"):
                opt_ttl      = st.toggle("TTL OS Fingerprinting", value=False)
                opt_hostname = st.toggle("Resolver Hostnames (DNS inverso)", value=False)
                custom_iface = st.text_input(
                    "Interfaz (dejar vacío = auto)",
                    value=st.session_state.config.get("default_interface", ""),
                    help="En Linux: eth0, wlan0 · En Windows: 'Wi-Fi', 'Ethernet' · Vacío = auto-detectado",
                )
                if st.session_state.config.get("debug_mode", False) and "Activo" in scan_mode:
                    st.code(f"Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst='{target_net}')", language="python")

            if st.button("🔍 Iniciar Descubrimiento", type="primary", use_container_width=True):
                from utils.network_detector import get_scapy_iface
                _raw_iface = custom_iface.strip() or st.session_state.net_iface or None
                iface = get_scapy_iface(_raw_iface)

                st.caption("Consola en vivo:")
                _scapy_console = st.empty()
                _scapy_logs    = []
                def _scapy_log(msg):
                    _scapy_logs.append(msg)
                    _scapy_console.code("\n".join(_scapy_logs), language="bash")

                with st.spinner("Escaneando..."):
                    if "Pasivo" in scan_mode:
                        res_scapy = run_passive_sniff(interface=iface, duration=passive_dur, log_fn=_scapy_log)
                    else:
                        res_scapy = run_arp_scan(
                            interface=iface, target_range=target_net, log_fn=_scapy_log,
                            ttl_fingerprint=opt_ttl, resolve_hostnames=opt_hostname
                        )

                if "error" in res_scapy:
                    st.error(res_scapy["error"])
                    _os = st.session_state.net_os
                    if _os == "Windows":
                        st.info("En Windows: instala Npcap y ejecuta la terminal como Administrador.")
                    else:
                        st.info("Ejecuta con privilegios root: sudo venv/bin/python -m streamlit run app.py")
                else:
                    st.session_state['last_arp'] = res_scapy
                    found = res_scapy['hosts_found']
                    spoof_count = len(res_scapy.get("arp_spoofing_alerts", []))
                    new_count   = len(res_scapy.get("baseline_report", {}).get("new", []))
                    if spoof_count:
                        st.error(f"⚠️ {spoof_count} alerta(s) ARP Spoofing detectadas!")
                    if new_count:
                        st.warning(f"🔴 {new_count} dispositivo(s) NO autorizados en la red!")
                    st.success(f"Completado — {found} dispositivo(s) encontrado(s)")
                    st.rerun()

        # ── RESULTADOS ───────────────────────────────────────────────────────
        with map_col:
            if 'last_arp' in st.session_state:
                arp_data = st.session_state['last_arp']
                tab_mapa, tab_devs, tab_alerts, tab_base = st.tabs([
                    "🗺️ Topología", "💻 Dispositivos", "⚠️ Alertas", "🛡️ Baseline"
                ])

                with tab_mapa:
                    _render_network_graph(arp_data, st.session_state.get('last_scan'))
                    delta = arp_data.get("delta", {})
                    if delta.get("new") or delta.get("disappeared"):
                        d_col1, d_col2 = st.columns(2)
                        with d_col1:
                            if delta["new"]:
                                st.markdown(f"**Nuevos desde último escaneo ({len(delta['new'])}):**")
                                for nd in delta["new"]:
                                    st.markdown(f"<span style='color:#00FF88'>+ {nd['ip']} — {nd.get('vendor','')}</span>", unsafe_allow_html=True)
                        with d_col2:
                            if delta["disappeared"]:
                                st.markdown(f"**Desaparecidos ({len(delta['disappeared'])}):**")
                                for gd in delta["disappeared"]:
                                    st.markdown(f"<span style='color:#FF4444'>- {gd['ip']} — {gd.get('vendor','')}</span>", unsafe_allow_html=True)

                with tab_devs:
                    mode_badge = "🟢 ACTIVO" if arp_data.get("mode") == "active" else "🔵 PASIVO"
                    st.caption(f"Modo: {mode_badge} | Interface: `{arp_data.get('interface','?')}`")
                    for device in arp_data.get("devices", []):
                        baseline_data = load_baseline()
                        is_auth  = device["mac"].lower() in baseline_data["authorized_macs"]
                        border   = "#00E5FF" if is_auth else "#FF4444"
                        auth_tag = "✅ Autorizado" if is_auth else "🔴 Desconocido"
                        os_hint  = device.get("os_hint", "")
                        hostname = device.get("hostname", "")
                        extra    = ""
                        if os_hint and os_hint != "N/A":
                            extra += f" | 🖥️ {os_hint}"
                        if hostname:
                            extra += f" | 🌐 {hostname}"
                        st.markdown(f"""
                            <div style="background:#161B22;border-left:4px solid {border};padding:10px;border-radius:4px;margin-bottom:5px;">
                                <b style="color:{border};">{auth_tag}</b>
                                &nbsp;&nbsp;📍 <b>{device['ip']}</b> &nbsp; 🆔 <code>{device['mac']}</code>
                                &nbsp; 🏭 <span style="color:#8B949E;">{device.get('vendor','Desconocido')}</span>{extra}
                            </div>
                        """, unsafe_allow_html=True)

                with tab_alerts:
                    spoof_alerts = arp_data.get("arp_spoofing_alerts", [])
                    baseline_rep = arp_data.get("baseline_report", {})

                    if not spoof_alerts and not baseline_rep.get("new") and not baseline_rep.get("missing"):
                        st.success("Sin alertas — red dentro de parámetros normales.")

                    if spoof_alerts:
                        st.markdown("#### Alertas ARP Spoofing / MITM")
                        for alert in spoof_alerts:
                            color = "#FF3333" if alert["severity"] == "CRITICO" else "#FF8800"
                            st.markdown(f"""
                                <div style="background:#1A0000;border-left:4px solid {color};padding:12px;border-radius:4px;margin-bottom:6px;">
                                    <b style="color:{color};">[{alert['severity']}] {alert['type']}</b><br>
                                    <span style="color:#C9D1D9;">{alert['detail']}</span><br>
                                    <small style="color:#8B949E;">{alert['indicator']}</small>
                                </div>
                            """, unsafe_allow_html=True)

                    if baseline_rep.get("new"):
                        st.markdown("#### Dispositivos NO autorizados")
                        for d in baseline_rep["new"]:
                            st.markdown(f"""
                                <div style="background:#1A1000;border-left:4px solid #FF8800;padding:10px;border-radius:4px;margin-bottom:5px;">
                                    <b style="color:#FF8800;">INTRUSO DETECTADO</b> &nbsp;
                                    📍 {d['ip']} &nbsp; 🆔 <code>{d['mac']}</code> &nbsp;
                                    🏭 {d.get('vendor','Desconocido')}
                                </div>
                            """, unsafe_allow_html=True)

                    if baseline_rep.get("missing"):
                        st.markdown("#### Dispositivos autorizados ausentes")
                        for d in baseline_rep["missing"]:
                            alias = d.get("alias") or d.get("mac", "?")
                            st.markdown(f"""
                                <div style="background:#001A1A;border-left:4px solid #00BFFF;padding:10px;border-radius:4px;margin-bottom:5px;">
                                    <b style="color:#00BFFF;">AUSENTE</b> &nbsp;
                                    🆔 <code>{d.get('mac','?')}</code> &nbsp; ({alias})
                                </div>
                            """, unsafe_allow_html=True)

                with tab_base:
                    st.markdown("#### Gestión de Baseline (Dispositivos Autorizados)")
                    current_baseline = load_baseline()
                    authorized_macs  = current_baseline.get("authorized_macs", {})

                    if authorized_macs:
                        st.caption(f"Baseline activa — {len(authorized_macs)} MAC(s) autorizadas | Actualizada: {current_baseline.get('last_updated','?')[:10]}")
                        for mac, info in authorized_macs.items():
                            b_col1, b_col2 = st.columns([4, 1])
                            with b_col1:
                                st.markdown(f"✅ `{mac}` — {info.get('vendor','')} | última IP: `{info.get('ip_last_seen','?')}`")
                            with b_col2:
                                if st.button("Revocar", key=f"revoke_{mac}"):
                                    remove_from_baseline(mac)
                                    st.rerun()
                        st.divider()
                    else:
                        st.info("No hay baseline configurada. Marca los dispositivos actuales como autorizados.")

                    st.markdown("**Agregar dispositivos del escaneo actual al Baseline:**")
                    devices_to_add = []
                    for d in arp_data.get("devices", []):
                        label = f"{d['ip']} — {d['mac']} ({d.get('vendor','?')})"
                        already = d["mac"].lower() in authorized_macs
                        if st.checkbox(label, value=already, key=f"bl_{d['mac']}"):
                            devices_to_add.append(d)

                    if st.button("💾 Guardar Baseline", type="primary", use_container_width=True):
                        save_baseline(devices_to_add)
                        st.success(f"Baseline guardada — {len(devices_to_add)} dispositivo(s) autorizados.")
                        st.rerun()

            else:
                st.info("Presiona 'Iniciar Descubrimiento' para mapear la red local.")

    with t_web:
        st.subheader("🕸️ Web Application Enumerator")
        col_w1, col_w2 = st.columns([1, 2])
        
        with col_w1:
            st.markdown("""
                Este módulo realiza **Fuzzing de Directorios** y **Fingerprinting** de cabeceras HTTP para identificar superficies de ataque web.
            """)
            web_target = st.text_input("URL / Host del Servidor", "127.0.0.1", key="web_t")
            
            if st.button("🚀 Iniciar Auditoría Web", width='stretch', type="primary"):
                from scanners.web_engine import run_web_enum
                st.caption("Consola en vivo:")
                _web_console = st.empty()
                _web_logs = []
                def _web_log(msg):
                    _web_logs.append(msg)
                    _web_console.code("\n".join(_web_logs), language="bash")
                with st.spinner("Escaneando..."):
                    res_web = run_web_enum(web_target, log_fn=_web_log)
                if "error" in res_web:
                    st.error(f"Error: {res_web['error']}")
                else:
                    st.session_state['last_web'] = res_web
                    st.success("¡Análisis Web finalizado!")

        with col_w2:
            if 'last_web' in st.session_state:
                w = st.session_state['last_web']

                # --- Fingerprinting ---
                fc1, fc2 = st.columns(2)
                with fc1:
                    st.markdown(f"**Servidor:** `{w['server']}`")
                    techs = w.get('detected_techs', [])
                    tech_str = ", ".join(techs) if techs else w.get('tech', 'Desconocida')
                    st.markdown(f"**Tecnologías:** `{tech_str}`")
                with fc2:
                    js_count = w.get('js_bundles_scanned', 0)
                    st.markdown(f"**Bundles JS escaneados:** `{js_count}`")
                    robots = w.get('robots_private_paths', [])
                    if robots:
                        st.markdown(f"**Rutas en robots.txt:** `{len(robots)}`")

                # --- CORS issues ---
                cors_issues = w.get('cors_issues', [])
                if cors_issues:
                    for ci in cors_issues:
                        sev_color = "#FF7F50" if ci.get('severity') == 'Alto' else "#FFD700"
                        st.markdown(f"""<div style="background:#161B22;border-left:4px solid {sev_color};padding:10px;border-radius:4px;margin-bottom:5px;">
                            <b style="color:{sev_color};">[{ci.get('severity','Medio')}] CORS: {ci.get('type','')}</b><br>
                            <small style="color:#8B949E;">{ci.get('detail','')}</small>
                        </div>""", unsafe_allow_html=True)

                # --- Cookie issues ---
                cookie_issues = w.get('cookie_issues', [])
                if cookie_issues:
                    with st.expander(f"🍪 {len(cookie_issues)} cookie(s) sin flags de seguridad"):
                        for ci in cookie_issues:
                            st.markdown(f"- `{ci['cookie']}` — faltan: **{', '.join(ci['missing_flags'])}**")

                # --- GraphQL ---
                gql = w.get('graphql', {})
                if gql.get('exposed'):
                    st.error(f"🔓 GraphQL introspection expuesta en `{gql.get('endpoint','')}` — el esquema completo es público")
                elif gql.get('endpoint'):
                    st.info(f"ℹ️ GraphQL detectado en `{gql.get('endpoint','')}` — introspección deshabilitada")

                # --- Source maps ---
                smaps = w.get('exposed_source_maps', [])
                if smaps:
                    with st.expander(f"🗺️ {len(smaps)} source map(s) expuesto(s) — código fuente accesible"):
                        for sm in smaps:
                            st.markdown(f"- `{sm['url'].split('/')[-1]}` ({sm['size_bytes']} bytes) — [{sm['url']}]({sm['url']})")

                # ═══════════════════════════════════════════════════════
                # SECRETOS EN JS BUNDLES (mayor prioridad — SPAs/React)
                # ═══════════════════════════════════════════════════════
                js_sec = w.get('js_secrets', [])
                if js_sec:
                    st.error(f"🚨 {len(js_sec)} SECRETO(S) EN BUNDLES JAVASCRIPT — API Keys embebidas en el frontend")
                    for sec in js_sec:
                        js_url_short = sec.get('js_url', '').split('/')[-1][:60]
                        with st.expander(f"🔑 {sec['type']}: `{sec['masked']}` — [{js_url_short}]"):
                            st.code(sec['raw'], language="text")
                            st.caption(f"Bundle: {sec.get('js_url','')}")
                            st.caption(f"Contexto: ...{sec['context']}...")
                    st.divider()

                # ═══════════════════════════════════════════════════════
                # SECRETOS EN ARCHIVOS/RUTAS REALES (no soft-404)
                # ═══════════════════════════════════════════════════════
                path_secrets = [e for e in w.get('found_paths', []) if e.get('secrets')]
                if path_secrets:
                    st.error(f"🚨 {sum(len(e['secrets']) for e in path_secrets)} SECRETO(S) EN ARCHIVOS EXPUESTOS")
                    for entry in path_secrets:
                        st.markdown(f"**`{entry['path']}`** ({entry['content_type']}, {entry['size_bytes']} bytes):")
                        for sec in entry['secrets']:
                            with st.expander(f"🔑 {sec['type']}: `{sec['masked']}`"):
                                st.code(sec['raw'], language="text")
                                st.caption(f"Contexto: ...{sec['context']}...")
                    st.divider()

                if not js_sec and not path_secrets:
                    total_sec = w.get('total_secrets_found', 0)
                    if total_sec == 0:
                        st.success("No se detectaron secretos expuestos.")

                # --- Cabeceras de seguridad faltantes ---
                missing = w.get('missing_security_headers', [])
                if missing:
                    st.warning(f"⚠️ Cabeceras de seguridad ausentes: {', '.join(missing)}")

                # --- Tabla de rutas REALES descubiertas (sin soft-404s) ---
                real_paths = w.get('found_paths', [])
                if real_paths:
                    st.write(f"### Rutas Reales Descubiertas ({len(real_paths)})")
                    import pandas as pd
                    df_web = pd.DataFrame([
                        {
                            "path":         e["path"],
                            "status":       e["status"],
                            "code":         e["code"],
                            "size (bytes)": e.get("size_bytes", ""),
                            "content_type": e.get("content_type", ""),
                            "secretos":     len(e.get("secrets", [])),
                            "snippet":      e.get("snippet", "")[:80],
                        }
                        for e in real_paths
                    ])
                    st.dataframe(df_web, use_container_width=True, hide_index=True)
                else:
                    baseline = w.get('soft404_baseline_size', 0)
                    st.info(f"Todas las rutas devolvieron el mismo HTML ({baseline} bytes) — SPA detectada. Los secretos se buscaron en los {js_count} bundles JS.")
            else:
                st.info("Ingresa un objetivo (ej. google.com o 127.0.0.1) para iniciar.")

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: SSL/TLS ANALYZER
    # ══════════════════════════════════════════════════════════════════════════
    with t_ssl:
        st.subheader("🔐 SSL/TLS Analyzer")
        ssl_col1, ssl_col2 = st.columns([1, 2])

        with ssl_col1:
            st.markdown("Audita el certificado, versiones de protocolo, cipher suites y vulnerabilidades conocidas (POODLE, HEARTBLEED, BEAST).")
            ssl_host = st.text_input("Host / Dominio", "example.com", key="ssl_host_input")
            ssl_port = st.number_input("Puerto", value=443, min_value=1, max_value=65535, key="ssl_port_input")

            if st.button("🔐 Analizar SSL/TLS", type="primary", use_container_width=True):
                _ssl_console = st.empty()
                _ssl_logs    = []
                def _ssl_log(msg):
                    _ssl_logs.append(msg)
                    _ssl_console.code("\n".join(_ssl_logs), language="bash")
                with st.spinner("Analizando SSL/TLS..."):
                    res_ssl = run_ssl_analysis(ssl_host, int(ssl_port), log_fn=_ssl_log)
                if "error" in res_ssl and not res_ssl.get("findings"):
                    st.error(f"Error: {res_ssl.get('error','')}")
                else:
                    st.session_state['last_ssl'] = res_ssl
                    s = res_ssl.get("summary", {})
                    if s.get("criticos", 0):
                        st.error(f"{s['criticos']} hallazgo(s) CRÍTICO(S)")
                    elif s.get("altos", 0):
                        st.warning(f"{s['altos']} hallazgo(s) ALTO(S)")
                    else:
                        st.success("Análisis SSL completado")
                    st.rerun()

        with ssl_col2:
            if 'last_ssl' in st.session_state:
                ssl_data = st.session_state['last_ssl']
                cert     = ssl_data.get("certificate", {})
                proto    = ssl_data.get("protocols", {})
                hsts     = ssl_data.get("hsts", {})

                # ── Certificado ──────────────────────────────────────────
                st.markdown("#### Certificado")
                if cert.get("ok"):
                    days = cert.get("days_left", 0)
                    days_color = "#FF3333" if days < 0 else ("#FF8800" if days < 30 else "#00E676")
                    c1, c2, c3 = st.columns(3)
                    c1.metric("CN", cert.get("subject_cn", "?")[:30])
                    c2.metric("Emisor", cert.get("issuer_o", "?")[:20])
                    c3.metric("Días restantes", days, delta=None)
                    st.markdown(f"""
                        <div style="background:#161B22;border-left:4px solid {days_color};padding:8px;border-radius:4px;margin-bottom:8px;">
                            <small style="color:#8B949E;">
                            Expira: <b style="color:{days_color};">{cert.get('expiry_date','?')}</b>
                            &nbsp;|&nbsp; Protocolo negociado: <b style="color:#00E5FF;">{cert.get('negotiated_protocol','?')}</b>
                            &nbsp;|&nbsp; Self-signed: <b>{'⚠️ SÍ' if cert.get('self_signed') else '✅ No'}</b>
                            </small>
                        </div>
                    """, unsafe_allow_html=True)

                # ── Protocolos ───────────────────────────────────────────
                st.markdown("#### Versiones de Protocolo")
                proto_cols = st.columns(4)
                for i, (name, supported) in enumerate(proto.items()):
                    color  = "#FF3333" if (supported and name in ("TLS 1.0", "TLS 1.1")) else ("#00E676" if supported else "#555555")
                    status = "HABILITADO" if supported else ("N/A" if supported is None else "deshabilitado")
                    proto_cols[i % 4].markdown(
                        f"<div style='background:#161B22;border:1px solid {color};padding:8px;border-radius:4px;text-align:center;'>"
                        f"<b style='color:{color};'>{name}</b><br><small style='color:#8B949E;'>{status}</small></div>",
                        unsafe_allow_html=True
                    )

                # ── HSTS ─────────────────────────────────────────────────
                st.markdown("#### HSTS")
                if hsts.get("present"):
                    st.success(f"HSTS configurado: `{hsts.get('value','')[:80]}`")
                else:
                    st.error("HSTS no configurado — vulnerable a ataques de downgrade a HTTP")

                # ── Hallazgos ────────────────────────────────────────────
                findings = ssl_data.get("findings", [])
                if findings:
                    st.markdown(f"#### Hallazgos ({len(findings)})")
                    _SEV_COLOR = {"CRÍTICO": "#FF3333", "ALTO": "#FF8800", "MEDIO": "#FFD700", "BAJO": "#8B949E"}
                    for f in findings:
                        fc = _SEV_COLOR.get(f["severity"], "#8B949E")
                        st.markdown(f"""
                            <div style="background:#161B22;border-left:4px solid {fc};padding:10px;border-radius:4px;margin-bottom:6px;">
                                <b style="color:{fc};">[{f['severity']}] {f['id']}</b> — {f['title']}<br>
                                <small style="color:#C9D1D9;">{f['detail']}</small><br>
                                <small style="color:#8B949E;">✅ {f['remediation']}</small><br>
                                <small style="color:#555;">📋 {f.get('compliance','')}</small>
                            </div>
                        """, unsafe_allow_html=True)
                else:
                    st.success("Sin hallazgos — configuración SSL/TLS correcta.")
            else:
                st.info("Ingresa un host y presiona 'Analizar SSL/TLS'.")

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: EMAIL SECURITY
    # ══════════════════════════════════════════════════════════════════════════
    with t_email:
        st.subheader("📧 Email Security Checker")
        em_col1, em_col2 = st.columns([1, 2])

        with em_col1:
            st.markdown("Audita los registros DNS de seguridad del correo: **SPF**, **DMARC**, **DKIM**, **MX** y banner SMTP. Esencial para detectar vulnerabilidad a **email spoofing** y **phishing**.")
            em_domain = st.text_input("Dominio a analizar", "ejemplo.com", key="email_domain_input")

            if st.button("📧 Analizar Seguridad de Email", type="primary", use_container_width=True):
                _em_console = st.empty()
                _em_logs    = []
                def _em_log(msg):
                    _em_logs.append(msg)
                    _em_console.code("\n".join(_em_logs), language="bash")
                with st.spinner("Consultando registros DNS..."):
                    res_email = run_email_security_check(em_domain, log_fn=_em_log)
                if "error" in res_email and not res_email.get("findings"):
                    st.error(f"Error: {res_email.get('error','')}")
                else:
                    st.session_state['last_email'] = res_email
                    s = res_email.get("summary", {})
                    if s.get("criticos", 0):
                        st.error(f"{s['criticos']} hallazgo(s) CRÍTICO(S) — dominio vulnerable a spoofing")
                    elif s.get("altos", 0):
                        st.warning(f"{s['altos']} hallazgo(s) de severidad ALTA")
                    else:
                        st.success("Análisis de email completado")
                    st.rerun()

        with em_col2:
            if 'last_email' in st.session_state:
                em_data = st.session_state['last_email']
                spf     = em_data.get("spf",   {})
                dmarc   = em_data.get("dmarc",  {})
                dkim    = em_data.get("dkim",   {})
                mx_data = em_data.get("mx",     {})

                # ── Status cards ─────────────────────────────────────────
                st.markdown("#### Estado de Registros DNS")
                sc1, sc2, sc3, sc4 = st.columns(4)

                def _status_card(col, label, present, severity):
                    _sev_c = {"CRÍTICO": "#FF3333", "ALTO": "#FF8800", "MEDIO": "#FFD700", "OK": "#00E676", "BAJO": "#8B949E"}
                    color  = "#00E676" if present else _sev_c.get(severity, "#FF3333")
                    icon   = "✅" if present else "❌"
                    col.markdown(
                        f"<div style='background:#161B22;border:1px solid {color};padding:10px;border-radius:4px;text-align:center;'>"
                        f"<b style='color:{color};font-size:20px;'>{icon}</b><br>"
                        f"<b style='color:#E6EDF3;'>{label}</b><br>"
                        f"<small style='color:{color};'>{severity if not present else 'Configurado'}</small></div>",
                        unsafe_allow_html=True
                    )

                _status_card(sc1, "SPF",   spf.get("present", False),   spf.get("severity", "ALTO"))
                _status_card(sc2, "DMARC", dmarc.get("present", False), dmarc.get("severity", "CRÍTICO"))
                _status_card(sc3, "DKIM",  dkim.get("present", False),  dkim.get("severity", "MEDIO"))
                _status_card(sc4, "MX",    mx_data.get("present", False), "OK" if mx_data.get("present") else "ALTO")

                st.markdown("<br>", unsafe_allow_html=True)

                # ── Detalles de registros ────────────────────────────────
                if spf.get("present"):
                    st.markdown(f"**SPF:** `{spf.get('record','')[:120]}`")
                    st.caption(f"Política: **{spf.get('policy','')}** — {spf.get('description','')}")

                if dmarc.get("present"):
                    st.markdown(f"**DMARC:** `{dmarc.get('record','')[:120]}`")
                    st.caption(f"Política: **p={dmarc.get('policy','')}** — {dmarc.get('policy_desc','')} | pct={dmarc.get('pct',100)}%")

                if dkim.get("selectors"):
                    sels = ", ".join(f"`{s['selector']}`" for s in dkim["selectors"])
                    st.markdown(f"**DKIM** selectores encontrados: {sels}")

                if mx_data.get("records"):
                    with st.expander(f"MX Records ({len(mx_data['records'])})"):
                        for r in mx_data["records"]:
                            st.markdown(f"- Prioridad {r['priority']}: `{r['host']}`")

                smtp_b = em_data.get("smtp", {})
                if smtp_b.get("banner"):
                    with st.expander("Banner SMTP"):
                        st.code(smtp_b["banner"], language="text")

                # ── Hallazgos ────────────────────────────────────────────
                findings = em_data.get("findings", [])
                if findings:
                    st.markdown(f"#### Hallazgos ({len(findings)})")
                    _SEV_COLOR = {"CRÍTICO": "#FF3333", "ALTO": "#FF8800", "MEDIO": "#FFD700", "BAJO": "#8B949E"}
                    for f in findings:
                        fc = _SEV_COLOR.get(f["severity"], "#8B949E")
                        st.markdown(f"""
                            <div style="background:#161B22;border-left:4px solid {fc};padding:10px;border-radius:4px;margin-bottom:6px;">
                                <b style="color:{fc};">[{f['severity']}] {f['id']}</b> — {f['title']}<br>
                                <small style="color:#C9D1D9;">{f['detail']}</small><br>
                                <small style="color:#8B949E;">✅ {f['remediation']}</small><br>
                                <small style="color:#555;">📋 {f.get('compliance','')}</small>
                            </div>
                        """, unsafe_allow_html=True)
                else:
                    st.success("Sin hallazgos — seguridad de email correctamente configurada.")
            else:
                st.info("Ingresa un dominio (ej. empresa.com) y presiona 'Analizar'.")

elif selected == "Knowledge Base":
    from utils.knowledge_manager import (
        extraer_texto_pdf, guardar_en_base_conocimiento,
        listar_documentos, eliminar_documento,
        buscar_fragmentos_relevantes, contar_total_fragmentos,
    )

    # Session state for KB
    if 'kb_queries' not in st.session_state:
        st.session_state.kb_queries = 0
    if 'kb_historial' not in st.session_state:
        st.session_state.kb_historial = []
    if 'kb_borrar_confirmacion' not in st.session_state:
        st.session_state.kb_borrar_confirmacion = None

    st.title("Knowledge Base")
    st.markdown("<p style='color:#4A5568;margin-top:-8px;font-size:13px;'>Gestión de documentación y búsqueda semántica con RAG</p>", unsafe_allow_html=True)

    # ── MÉTRICAS REALES ──────────────────────────────────────────────────────
    docs_lista = listar_documentos()
    total_docs = len(docs_lista)
    total_fragmentos = contar_total_fragmentos()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"<div class='metric-card'><p class='metric-title'>DOCUMENTOS</p><p class='metric-value'>{total_docs}</p><small style='color:#00E5FF;'>Indexados en disco</small></div>", unsafe_allow_html=True)
    with col2:
        st.markdown(f"<div class='metric-card'><p class='metric-title'>FRAGMENTOS RAG</p><p class='metric-value'>{total_fragmentos:,}</p><small style='color:#8B949E;'>Bloques de 100 palabras</small></div>", unsafe_allow_html=True)
    with col3:
        st.markdown(f"<div class='metric-card'><p class='metric-title'>CONSULTAS HOY</p><p class='metric-value'>{st.session_state.kb_queries}</p><small style='color:#8B949E;'>Esta sesión</small></div>", unsafe_allow_html=True)
    with col4:
        _kb_key = (st.session_state.anthropic_key if st.session_state.ai_provider == "claude"
                   else st.session_state.gemini_key)
        ia_status = "ACTIVO" if _kb_key.strip() else "INACTIVO"
        ia_color  = "#39FF14" if _kb_key.strip() else "#FF4B4B"
        _kb_label = "Claude" if st.session_state.ai_provider == "claude" else "Gemini"
        st.markdown(f"<div class='metric-card'><p class='metric-title'>MOTOR IA</p><p class='metric-value' style='font-size:1.4rem;color:{ia_color};'>{ia_status}</p><small style='color:#8B949E;'>{_kb_label} API</small></div>", unsafe_allow_html=True)

    st.write("")
    col_docs, col_rag = st.columns([2, 1])

    # ── COLUMNA IZQUIERDA: DOCUMENTOS ────────────────────────────────────────
    with col_docs:
        st.subheader("📤 Cargar Documento")
        archivo_subido = st.file_uploader(
            "Sube normativas, manuales o políticas (PDF)",
            type="pdf",
            label_visibility="collapsed",
        )
        if archivo_subido is not None:
            if st.button("🧠 Indexar Documento", type="primary"):
                with st.spinner(f"Extrayendo texto de {archivo_subido.name}..."):
                    texto = extraer_texto_pdf(archivo_subido)
                    if texto.startswith("Error"):
                        st.error(texto)
                    else:
                        ruta = guardar_en_base_conocimiento(archivo_subido.name, texto)
                        n_palabras = len(texto.split())
                        st.success(f"✅ **{archivo_subido.name}** indexado — {n_palabras:,} palabras extraídas")
                        st.rerun()

        st.write("")
        st.subheader("📋 Documentos Indexados")
        filtro_kb = st.text_input("🔍 Filtrar documentos...", placeholder="Escribe para buscar...", label_visibility="collapsed")

        docs_filtrados = listar_documentos(filtro=filtro_kb)

        if not docs_filtrados:
            if total_docs == 0:
                st.info("No hay documentos indexados. Sube un PDF para comenzar.")
            else:
                st.info(f"No se encontraron documentos que coincidan con '{filtro_kb}'.")
        else:
            doc_colors = ["#00E5FF", "#39FF14", "#FF7F50", "#A855F7", "#FFD700", "#FF4B4B"]
            for i, doc in enumerate(docs_filtrados):
                color = doc_colors[i % len(doc_colors)]
                col_info, col_del = st.columns([5, 1])
                with col_info:
                    st.markdown(f"""
                        <div style="background-color:#161B22;border:1px solid #30363D;border-left:4px solid {color};
                                    padding:12px;border-radius:8px;margin-bottom:6px;">
                            <span style="font-weight:bold;color:white;">📄 {doc['nombre']}</span><br>
                            <small style="color:#8B949E;">
                                {doc['palabras']:,} palabras &nbsp;|&nbsp;
                                {doc['fragmentos']} fragmentos RAG &nbsp;|&nbsp;
                                {doc['tamano_kb']} KB &nbsp;|&nbsp;
                                <span style="color:{color};">● Indexado {doc['fecha']}</span>
                            </small>
                        </div>
                    """, unsafe_allow_html=True)
                with col_del:
                    st.write("")
                    if st.button("🗑️", key=f"del_{doc['archivo']}", help=f"Eliminar {doc['nombre']}"):
                        st.session_state.kb_borrar_confirmacion = doc['archivo']

        # Confirmación de borrado
        if st.session_state.kb_borrar_confirmacion:
            nombre_a_borrar = st.session_state.kb_borrar_confirmacion
            st.warning(f"¿Eliminar **{nombre_a_borrar}** de la base de conocimiento?")
            bc1, bc2 = st.columns(2)
            with bc1:
                if st.button("Sí, eliminar", type="primary"):
                    if eliminar_documento(nombre_a_borrar):
                        st.success(f"Documento eliminado.")
                    st.session_state.kb_borrar_confirmacion = None
                    st.rerun()
            with bc2:
                if st.button("Cancelar"):
                    st.session_state.kb_borrar_confirmacion = None
                    st.rerun()

    # ── COLUMNA DERECHA: RAG ─────────────────────────────────────────────────
    with col_rag:
        st.markdown("""
            <div style="background:#10151E;border:1px solid #1E2733;border-left:3px solid #00D4FF;padding:14px;border-radius:8px;margin-bottom:12px;">
                <p style="margin:0;font-weight:700;color:#00D4FF;font-size:13px;">Consulta RAG</p>
                <p style="color:#4A5568;font-size:11px;margin:4px 0 0 0;">
                    Búsqueda semántica en documentos + análisis con IA
                </p>
            </div>
        """, unsafe_allow_html=True)

        prompt_rag = st.text_area(
            "Pregunta",
            placeholder="Ej: ¿Qué dice el NIST sobre gestión de parches?\nEj: Controles ISO para acceso remoto\nEj: OWASP vulnerabilidades en APIs",
            height=110,
            label_visibility="collapsed",
        )

        if st.button("🚀 Consultar Base de Conocimiento", width='stretch', type="primary"):
            if not prompt_rag.strip():
                st.warning("Escribe una pregunta primero.")
            elif not (st.session_state.anthropic_key if st.session_state.ai_provider == "claude" else st.session_state.gemini_key).strip():
                st.error("Configura tu API Key en Settings para usar el motor RAG.")
            elif total_docs == 0:
                st.error("No hay documentos indexados. Sube al menos un PDF primero.")
            else:
                with st.spinner("Buscando fragmentos relevantes..."):
                    fragmentos = buscar_fragmentos_relevantes(prompt_rag, max_fragmentos=6)

                if not fragmentos:
                    st.warning("No se encontraron fragmentos relevantes para esa consulta en los documentos indexados.")
                else:
                    st.markdown("**Fragmentos recuperados:**")
                    for frag in fragmentos:
                        rel_color = "#39FF14" if frag['relevancia'] >= 70 else "#FFD700" if frag['relevancia'] >= 40 else "#8B949E"
                        st.markdown(f"""
                            <div style="background:#0B0E14;border:1px solid #30363D;padding:10px;border-radius:6px;margin-bottom:6px;">
                                <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
                                    <b style="font-size:11px;color:#00E5FF;">{frag['fuente']}</b>
                                    <span style="background:{rel_color}22;color:{rel_color};font-size:10px;padding:1px 6px;border-radius:4px;">
                                        {frag['relevancia']}% relevante
                                    </span>
                                </div>
                                <p style="font-size:11px;color:#8B949E;margin:0;">"{frag['chunk'][:200]}..."</p>
                            </div>
                        """, unsafe_allow_html=True)

                    contexto_rag = "\n\n".join(
                        f"[{f['fuente']} — {f['relevancia']}% relevante]\n{f['chunk']}"
                        for f in fragmentos
                    )
                    contexto_tecnico = ""
                    if 'last_scan' in st.session_state:
                        s = st.session_state['last_scan']
                        puertos = [f"{p['port']}/{p['service']}" for h in s.get('hosts', []) for p in h.get('ports', [])]
                        contexto_tecnico = f"Último escaneo Nmap — objetivo: {s.get('target','')}, puertos: {', '.join(puertos[:20])}"

                    prompt_final = f"""Eres un analista de ciberseguridad de OtsuSearch.
Responde la pregunta del auditor basándote ÚNICAMENTE en los fragmentos de documentos proporcionados.
Cita la fuente (nombre del documento) cuando uses información de ella.
Si los documentos no contienen información suficiente, indícalo claramente.

FRAGMENTOS DE DOCUMENTOS RELEVANTES:
{contexto_rag}

{'CONTEXTO TÉCNICO DEL SISTEMA:' + chr(10) + contexto_tecnico if contexto_tecnico else ''}

PREGUNTA DEL AUDITOR:
{prompt_rag}

Responde en español, de forma estructurada y concisa."""

                    with st.spinner("Analizando con IA..."):
                        try:
                            if st.session_state.ai_provider == "claude":
                                import anthropic as _ant
                                _ant_client = _ant.Anthropic(api_key=st.session_state.anthropic_key)
                                _msg = _ant_client.messages.create(
                                    model=st.session_state.config.get("claude_model", "claude-opus-4-7"),
                                    max_tokens=4096,
                                    messages=[{"role": "user", "content": prompt_final}],
                                )
                                respuesta = _msg.content[0].text
                            else:
                                from google import genai
                                client = genai.Client(api_key=st.session_state.gemini_key)
                                response = client.models.generate_content(
                                    model=st.session_state.config.get("model", "gemini-2.5-flash"),
                                    contents=prompt_final,
                                )
                                respuesta = response.text
                            st.session_state.kb_queries += 1
                            st.session_state.kb_historial.insert(0, {
                                "pregunta":  prompt_rag[:80],
                                "respuesta": respuesta,
                                "fuentes":   list({f['fuente'] for f in fragmentos}),
                            })
                        except Exception as e:
                            st.error(f"Error al consultar IA: {e}")
                            respuesta = None

        # ── Historial de respuestas ──────────────────────────────────────────
        if st.session_state.kb_historial:
            st.write("---")
            st.markdown("**Historial de consultas**")
            for entry in st.session_state.kb_historial[:5]:
                with st.expander(f"💬 {entry['pregunta']}{'...' if len(entry['pregunta']) == 80 else ''}"):
                    st.markdown(f"**Fuentes:** `{'`, `'.join(entry['fuentes'])}`")
                    st.markdown(entry['respuesta'])

elif selected == "Reports":
    st.title("Reportes")
    
    # Verificamos qué datos tenemos disponibles
    has_nmap = 'last_scan' in st.session_state
    has_scapy = 'last_arp' in st.session_state
    has_web = 'last_web' in st.session_state

    if not (has_nmap or has_scapy or has_web):
        st.warning("⚠️ No hay datos para reportar. Realiza al menos un escaneo.")
    else:
        st.success(f"Datos listos para procesar: {'Nmap ' if has_nmap else ''}{'Scapy ' if has_scapy else ''}{'Web' if has_web else ''}")
        
        if st.button("🚀 GENERAR AUDITORÍA INTEGRAL", type="primary"):
            with st.spinner("Generando auditoría integral con IA..."):
                # 1. Obtener análisis IA
                ai_report = analizar_auditoria_ia(
                    st.session_state.get('last_scan'),
                    st.session_state.get('last_arp'),
                    st.session_state.get('last_web'),
                    provider=st.session_state.ai_provider,
                    gemini_key=st.session_state.gemini_key,
                    anthropic_key=st.session_state.anthropic_key,
                )
                
                # 2. Generar PDF
                from utils.pdf_generator import generar_reporte_final
                pdf_path = generar_reporte_final(
                    st.session_state.get('last_scan'),
                    st.session_state.get('last_arp'),
                    st.session_state.get('last_web'),
                    ai_report,
                    ssl_data=st.session_state.get('last_ssl'),
                    email_data=st.session_state.get('last_email'),
                )
                
                st.session_state['final_pdf'] = pdf_path
                st.session_state['final_ai_text'] = ai_report

        if 'final_pdf' in st.session_state:
            st.markdown("---")
            st.subheader("📝 Vista Previa del Informe")
            st.markdown(st.session_state['final_ai_text'])
            
            with open(st.session_state['final_pdf'], "rb") as f:
                st.download_button(
                    label="📥 Descargar Reporte PDF Oficial",
                    data=f,
                    file_name="OtsuSearch_Full_Audit.pdf",
                    mime="application/pdf",
                    width='stretch'
                )

elif selected == "Settings":
    from utils.config_manager import save_config, load_config

    # Cargamos configuración actual
    current_cfg = load_config()

    st.title("Configuración")
    tk, te, tn = st.tabs(["🔑 Claves API", "🤖 Motor IA", "🌐 Red"])

    with tk:
        st.subheader("Proveedor de IA")
        provider_options = ["gemini", "claude"]
        provider_labels  = ["🔵 Google Gemini", "🟣 Anthropic Claude"]
        current_provider = current_cfg.get("ai_provider", "gemini")
        provider_idx     = provider_options.index(current_provider) if current_provider in provider_options else 0
        selected_provider = st.radio(
            "Motor de análisis activo",
            options=provider_options,
            format_func=lambda x: provider_labels[provider_options.index(x)],
            index=provider_idx,
            horizontal=True,
        )

        st.divider()
        st.subheader("Google Gemini")
        gemini_key = st.text_input("Gemini API Key", value=current_cfg.get("gemini_key", ""), type="password")

        st.subheader("Anthropic Claude")
        anthropic_key = st.text_input("Anthropic API Key", value=current_cfg.get("anthropic_key", ""), type="password",
                                      help="Obtén tu clave en console.anthropic.com")

        shodan_key = st.text_input("Shodan API Key (Opcional)", type="password")

        if st.button("💾 Guardar y Probar Conexión", type="primary"):
            current_cfg["gemini_key"]    = gemini_key
            current_cfg["anthropic_key"] = anthropic_key
            current_cfg["ai_provider"]   = selected_provider
            save_config(current_cfg)
            st.session_state.gemini_key    = gemini_key
            st.session_state.anthropic_key = anthropic_key
            st.session_state.ai_provider   = selected_provider
            st.success(f"✅ Configuración guardada. Proveedor activo: **{selected_provider.capitalize()}**")

    with te:
        current_provider_te = current_cfg.get("ai_provider", "gemini")
        if current_provider_te == "claude":
            st.info("Proveedor activo: **Anthropic Claude**")
            claude_models = ["claude-opus-4-7", "claude-sonnet-4-6", "claude-haiku-4-5"]
            current_claude = current_cfg.get("claude_model", "claude-opus-4-7")
            claude_idx = claude_models.index(current_claude) if current_claude in claude_models else 0
            claude_modelo = st.selectbox("Modelo Claude", claude_models, index=claude_idx)
            temp = st.slider("Temperatura", 0.0, 1.0, float(current_cfg.get("temperature", 0.3)))
            if st.button("🔄 Actualizar Motor"):
                current_cfg["claude_model"] = claude_modelo
                current_cfg["temperature"]  = temp
                save_config(current_cfg)
                st.info(f"Motor Claude configurado en {claude_modelo}")
        else:
            st.info("Proveedor activo: **Google Gemini**")
            gemini_models = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-pro"]
            current_gemini = current_cfg.get("model", "gemini-2.5-flash")
            gemini_idx = gemini_models.index(current_gemini) if current_gemini in gemini_models else 0
            modelo = st.selectbox("Modelo Gemini", gemini_models, index=gemini_idx)
            temp = st.slider("Temperatura", 0.0, 1.0, float(current_cfg.get("temperature", 0.3)))
            if st.button("🔄 Actualizar Motor"):
                current_cfg["model"]       = modelo
                current_cfg["temperature"] = temp
                save_config(current_cfg)
                st.info(f"Motor Gemini configurado en {modelo}")

    with tn:
        st.subheader("Configuración de Adaptadores")
        # Aquí resolvemos el problema que tuvimos con eth0/eth1
        interface = st.text_input("Interfaz de Red Predeterminada", value=current_cfg.get("default_interface", "eth0"))
        default_net = st.text_input("Rango de Red Favorito", value=current_cfg.get("default_range", "192.168.1.0/24"))
        
        if st.button("📡 Aplicar Ajustes de Red"):
            current_cfg["default_interface"] = interface
            current_cfg["default_range"] = default_net
            save_config(current_cfg)
            st.success("Ajustes de red aplicados.")
        
        st.divider()
        
        st.subheader("🛡️ Control de Alcance (Scope)")
        exclusiones = st.text_area("IPs Excluidas (Separadas por coma)", 
                                   value=current_cfg.get("excluded_ips", ""))
        
        st.divider()
        
        st.subheader("🛠️ Opciones Avanzadas")
        god_mode = st.toggle("Debug Mode", value=current_cfg.get("debug_mode", False))
        st.caption("Muestra los comandos crudos (Raw Commands) que OtsuSearch ejecuta en el sistema.")

        if st.button("💾 Guardar Ajustes de Red"):
            current_cfg["excluded_ips"] = exclusiones
            current_cfg["debug_mode"] = god_mode # Guardamos el estado
            save_config(current_cfg)
            st.session_state.config = current_cfg # Actualizamos sesión
            st.success("Configuración de red actualizada.")