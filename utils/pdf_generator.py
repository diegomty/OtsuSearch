"""
pdf_generator.py  —  Sentinel-Core AI  |  Motor de Reportes Profesionales v2
===========================================================================
Drop-in replacement del pdf_generator.py original (fpdf → reportlab).
Firma de función idéntica al original:
    generar_reporte_final(scan_nmap, scan_scapy, scan_web, ai_analysis) → str

Requiere:  pip install reportlab
"""

import os
import re
import datetime

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

# ═══ PALETA ══════════════════════════════════════════════════════════════════
DARK_BG      = colors.HexColor("#0D1117")
PANEL_BG     = colors.HexColor("#161B22")
PANEL_ALT    = colors.HexColor("#1A2030")
BORDER_COLOR = colors.HexColor("#21262D")
HEADER_BG    = colors.HexColor("#1C2128")

ACCENT_CYAN  = colors.HexColor("#00D4FF")
ACCENT_RED   = colors.HexColor("#FF3B3B")
ACCENT_AMBER = colors.HexColor("#FFB800")
ACCENT_GREEN = colors.HexColor("#00E676")

TEXT_PRIMARY = colors.HexColor("#E6EDF3")
TEXT_MUTED   = colors.HexColor("#8B949E")
TEXT_DARK    = colors.HexColor("#0D1117")
WHITE        = colors.white

PAGE_W, PAGE_H = A4
MARGIN         = 15 * mm
FULL_W         = PAGE_W - 2 * MARGIN


# ═══ PÁGINA (cover + páginas) ════════════════════════════════════════════════
def _draw_cover(canv, doc):
    canv.saveState()
    canv.setFillColor(DARK_BG)
    canv.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)

    canv.setFillColor(ACCENT_CYAN)
    canv.rect(0, PAGE_H - 6*mm, PAGE_W, 6*mm, stroke=0, fill=1)
    canv.rect(0, 0, PAGE_W, 3*mm, stroke=0, fill=1)

    canv.setFillColor(colors.HexColor("#00D4FF18"))
    p = canv.beginPath()
    p.moveTo(PAGE_W - 120*mm, PAGE_H - 6*mm)
    p.lineTo(PAGE_W, PAGE_H - 6*mm)
    p.lineTo(PAGE_W, PAGE_H - 80*mm)
    p.close()
    canv.drawPath(p, stroke=0, fill=1)

    canv.setFillColor(colors.HexColor("#FFFFFF08"))
    for x in range(20, int(PAGE_W / mm), 12):
        for y in range(20, int(PAGE_H / mm), 12):
            canv.circle(x * mm, y * mm, 0.8 * mm, stroke=0, fill=1)
    canv.restoreState()


def _draw_page(canv, doc):
    canv.saveState()
    canv.setFillColor(DARK_BG)
    canv.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)

    canv.setFillColor(PANEL_BG)
    canv.rect(0, PAGE_H - 18*mm, PAGE_W, 18*mm, stroke=0, fill=1)
    canv.setFillColor(ACCENT_CYAN)
    canv.rect(0, PAGE_H - 18*mm, PAGE_W, 1*mm, stroke=0, fill=1)
    canv.setFillColor(TEXT_MUTED)
    canv.setFont("Helvetica", 7)
    canv.drawString(15*mm, PAGE_H - 11*mm,
                    "SENTINEL-CORE AI  ·  REPORTE DE AUDITORÍA DE SEGURIDAD  ·  CONFIDENCIAL")
    canv.setFillColor(ACCENT_CYAN)
    canv.drawRightString(PAGE_W - 15*mm, PAGE_H - 11*mm,
                         datetime.datetime.now().strftime("%Y-%m-%d"))

    canv.setFillColor(PANEL_BG)
    canv.rect(0, 0, PAGE_W, 12*mm, stroke=0, fill=1)
    canv.setFillColor(ACCENT_CYAN)
    canv.rect(0, 12*mm, PAGE_W, 0.5*mm, stroke=0, fill=1)
    canv.setFillColor(TEXT_MUTED)
    canv.setFont("Helvetica", 7)
    canv.drawString(15*mm, 4.5*mm,
                    "© Sentinel-Core AI Systems  ·  Documento Confidencial — Uso Interno Exclusivo")
    canv.drawRightString(PAGE_W - 15*mm, 4.5*mm, f"Página {doc.page}")
    canv.restoreState()


def _on_page(canv, doc):
    if doc.page == 1:
        _draw_cover(canv, doc)
    else:
        _draw_page(canv, doc)


# ═══ ESTILOS ══════════════════════════════════════════════════════════════════
def _styles():
    s = {}
    s['cover_label'] = ParagraphStyle('cl', fontName='Helvetica', fontSize=9,
                                       textColor=ACCENT_CYAN, spaceAfter=4)
    s['cover_title'] = ParagraphStyle('ct', fontName='Helvetica-Bold', fontSize=34,
                                       textColor=WHITE, leading=40, spaceAfter=6)
    s['cover_sub']   = ParagraphStyle('cs', fontName='Helvetica', fontSize=13,
                                       textColor=TEXT_MUTED, spaceAfter=16, leading=18)
    s['cover_meta']  = ParagraphStyle('cm', fontName='Helvetica', fontSize=9.5,
                                       textColor=TEXT_MUTED, spaceAfter=3)
    s['sec_hdr']     = ParagraphStyle('sh', fontName='Helvetica-Bold', fontSize=13,
                                       textColor=ACCENT_CYAN, spaceBefore=12,
                                       spaceAfter=6, leading=16)
    s['subsec']      = ParagraphStyle('ss', fontName='Helvetica-Bold', fontSize=10,
                                       textColor=WHITE, spaceBefore=8, spaceAfter=4,
                                       leading=14)
    s['body']        = ParagraphStyle('b', fontName='Helvetica', fontSize=9,
                                       textColor=TEXT_PRIMARY, leading=14,
                                       spaceAfter=5, alignment=TA_LEFT)
    s['body_muted']  = ParagraphStyle('bm', fontName='Helvetica', fontSize=8.5,
                                       textColor=TEXT_MUTED, leading=13, spaceAfter=3)
    s['bullet']      = ParagraphStyle('bu', fontName='Helvetica', fontSize=9,
                                       textColor=TEXT_PRIMARY, leading=14,
                                       spaceAfter=3, leftIndent=10)
    s['th']          = ParagraphStyle('th', fontName='Helvetica-Bold', fontSize=8.5,
                                       textColor=ACCENT_CYAN, alignment=TA_CENTER)
    s['tc']          = ParagraphStyle('tc', fontName='Helvetica', fontSize=8.5,
                                       textColor=TEXT_PRIMARY, alignment=TA_CENTER)
    s['tl']          = ParagraphStyle('tl', fontName='Helvetica', fontSize=8.5,
                                       textColor=TEXT_PRIMARY, alignment=TA_LEFT)
    s['tl_muted']    = ParagraphStyle('tlm', fontName='Helvetica-Oblique', fontSize=8,
                                       textColor=TEXT_MUTED, alignment=TA_LEFT)
    s['badge_w']     = ParagraphStyle('bw', fontName='Helvetica-Bold', fontSize=8,
                                       textColor=WHITE, alignment=TA_CENTER)
    s['badge_d']     = ParagraphStyle('bd', fontName='Helvetica-Bold', fontSize=8,
                                       textColor=TEXT_DARK, alignment=TA_CENTER)
    s['kpi_val']     = ParagraphStyle('kv', fontName='Helvetica-Bold', fontSize=24,
                                       textColor=WHITE, alignment=TA_CENTER, leading=28)
    s['kpi_lbl']     = ParagraphStyle('kl', fontName='Helvetica', fontSize=8,
                                       textColor=TEXT_MUTED, alignment=TA_CENTER)
    # Priority cards — smaller fonts to avoid overflow
    s['prio_label']  = ParagraphStyle('pl', fontName='Helvetica-Bold', fontSize=7.5,
                                       textColor=WHITE)
    s['prio_time']   = ParagraphStyle('pt', fontName='Helvetica-Bold', fontSize=11,
                                       textColor=WHITE, leading=14, spaceAfter=2)
    s['prio_item']   = ParagraphStyle('pi', fontName='Helvetica', fontSize=7.8,
                                       textColor=TEXT_PRIMARY, leading=11, spaceAfter=2)
    return s


# ═══ HELPERS ══════════════════════════════════════════════════════════════════
_BASE_TABLE_STYLE = [
    ('BACKGROUND', (0, 0), (-1, 0), HEADER_BG),
    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [PANEL_BG, PANEL_ALT]),
    ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
    ('LINEBELOW', (0, 0), (-1, 0), 0.8, ACCENT_CYAN),
    ('INNERGRID', (0, 1), (-1, -1), 0.3, BORDER_COLOR),
    ('TOPPADDING', (0, 0), (-1, -1), 6),
    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ('LEFTPADDING', (0, 0), (-1, -1), 6),
    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ('ROUNDEDCORNERS', [4]),
]


def _badge(text, bg_color, s, style_key='badge_w', w=18*mm):
    t = Table([[Paragraph(text, s[style_key])]], colWidths=[w], rowHeights=[5.5*mm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), bg_color),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROUNDEDCORNERS', [3]),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
    ]))
    return t


# Descripción legible de servicios comunes (cuando Nmap no devuelve versión)
_SERVICE_DESC = {
    'ssh':          'Servicio SSH estándar (OpenSSH esperado)',
    'http':         'Servidor HTTP',
    'https':        'Servidor HTTPS',
    'http-proxy':   'Proxy HTTP (servicio intermedio)',
    'ftp':          'Servidor FTP',
    'telnet':       'Telnet (protocolo sin cifrado)',
    'smb':          'Samba / SMB',
    'microsoft-ds': 'Microsoft DS / SMB',
    'mysql':        'Servidor MySQL',
    'postgresql':   'Servidor PostgreSQL',
    'ms-sql-s':     'Microsoft SQL Server',
    'rdp':          'Remote Desktop Protocol',
    'vnc':          'VNC (escritorio remoto)',
    'redis':        'Redis',
    'mongodb':      'MongoDB',
    'dns':          'Servidor DNS',
    'smtp':         'Servidor SMTP',
    'pop3':         'Servidor POP3',
    'imap':         'Servidor IMAP',
}


def _version_label(port_info: dict) -> str:
    product = (port_info.get('product') or '').strip()
    version = (port_info.get('version') or '').strip()
    service = (port_info.get('service') or '').strip().lower()
    if product or version:
        return f"{product} {version}".strip()
    if service in _SERVICE_DESC:
        return _SERVICE_DESC[service]
    return "Versión no identificada"


def _port_risk(port_number):
    critical = {21, 23, 445, 3306, 5432, 1433, 3389, 4444, 5900, 6379, 27017}
    high     = {22, 80, 8080, 8443, 443, 8000, 8888}
    try:
        p = int(port_number)
    except (ValueError, TypeError):
        p = 0
    if p in critical:
        return "CRÍTICO", ACCENT_RED
    if p in high:
        return "ALTO", ACCENT_RED
    return "MEDIO", ACCENT_AMBER


# ═══ PARSER MARKDOWN ═════════════════════════════════════════════════════════
def _md_inline(text: str) -> str:
    text = text.replace('&', '&amp;')
    text = re.sub(r'#(?![0-9a-fA-F]{6})', '', text)
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'(?<!\*)\*([^*]+?)\*(?!\*)', r'<i>\1</i>', text)
    text = re.sub(r'`(.+?)`',
                  r'<font face="Courier" color="#00E676">\1</font>', text)
    return text


def _markdown_to_flowables(md_text: str, s: dict) -> list:
    if not md_text:
        return [Paragraph("Sin análisis disponible.", s['body'])]

    md_text = md_text.replace('\r\n', '\n').replace('\r', '\n')
    md_text = re.sub(r'\n---+\n', '\n\n', md_text)  # quita divisores
    lines = md_text.split('\n')
    out = []
    prev_empty = False

    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            if not prev_empty:
                out.append(Spacer(1, 2*mm))
            prev_empty = True
            continue
        prev_empty = False

        indent = len(raw) - len(raw.lstrip(' '))
        is_indented = indent >= 2

        if stripped.startswith('### '):
            out.append(Paragraph(_md_inline(stripped[4:]), s['subsec']))
            continue
        if stripped.startswith('## '):
            out.append(Paragraph(_md_inline(stripped[3:]), s['subsec']))
            continue
        if stripped.startswith('# '):
            out.append(Paragraph(_md_inline(stripped[2:]), s['sec_hdr']))
            continue

        m_bullet = re.match(r'^[-*■]\s+(.+)', stripped)
        if m_bullet:
            content = _md_inline(m_bullet.group(1))
            if is_indented:
                sub_style = ParagraphStyle('sb', parent=s['bullet'], leftIndent=22,
                                           fontSize=8.5, textColor=TEXT_MUTED)
                out.append(Paragraph(
                    f'<font color="#8B949E">◦</font>  {content}', sub_style))
            else:
                out.append(Paragraph(
                    f'<font color="#00D4FF">■</font>  {content}', s['bullet']))
            continue

        m_num = re.match(r'^(\d+)\.\s+(.+)', stripped)
        if m_num:
            n, content = m_num.group(1), _md_inline(m_num.group(2))
            out.append(Paragraph(
                f'<font color="#00D4FF"><b>{n}.</b></font>  {content}', s['bullet']))
            continue

        out.append(Paragraph(_md_inline(stripped), s['body']))

    return out


def _calcular_risk_score(scan_nmap, scan_web, ssl_data, email_data):
    """Weighted risk score across all scan modules."""
    score = 0

    # Nmap: port risk weights
    if scan_nmap:
        critical_ports = {21, 23, 445, 3306, 5432, 1433, 3389, 4444, 5900, 6379, 27017}
        high_ports     = {22, 80, 8080, 8443, 443}
        for h in scan_nmap.get('hosts', []):
            for p in h.get('ports', []):
                try:
                    pn = int(p.get('port', 0))
                except (ValueError, TypeError):
                    pn = 0
                if pn in critical_ports:
                    score += 10
                elif pn in high_ports:
                    score += 4
                else:
                    score += 1

    # Web: secrets are critical
    if scan_web:
        score += len(scan_web.get('js_secrets', []))    * 15
        score += len(scan_web.get('cors_issues', []))   * 6
        score += len(scan_web.get('cookie_issues', [])) * 2
        if scan_web.get('graphql', {}).get('exposed'):
            score += 8

    # SSL findings
    _sev_w = {'CRÍTICO': 12, 'ALTO': 7, 'MEDIO': 3, 'BAJO': 1}
    if ssl_data:
        for f in ssl_data.get('findings', []):
            score += _sev_w.get(f.get('severity', 'BAJO'), 1)

    # Email findings
    if email_data:
        for f in email_data.get('findings', []):
            score += _sev_w.get(f.get('severity', 'BAJO'), 1)

    if score >= 60:
        return score, "CRÍTICO", ACCENT_RED
    if score >= 30:
        return score, "ALTO",    ACCENT_RED
    if score >= 10:
        return score, "MEDIO",   ACCENT_AMBER
    return score, "BAJO", ACCENT_GREEN


def _nivel_riesgo(total_ports, web_findings):
    score = total_ports + web_findings * 2
    if score > 10:
        return "CRÍTICO", ACCENT_RED
    if score > 4:
        return "ALTO", ACCENT_RED
    if score > 0:
        return "MEDIO", ACCENT_AMBER
    return "BAJO", ACCENT_GREEN


# ═══════════════════════════════════════════════════════════════════════════════
# FUNCIÓN PÚBLICA (firma idéntica al original)
# ═══════════════════════════════════════════════════════════════════════════════
def generar_reporte_final(scan_nmap, scan_scapy, scan_web, ai_analysis,
                          ssl_data=None, email_data=None,
                          client_name="", engagement_id="") -> str:
    os.makedirs("data/reports", exist_ok=True)
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join("data/reports", f"Sentinel_Pro_{ts}.pdf")

    total_hosts = scan_scapy.get('hosts_found', 0) if scan_scapy else 0
    all_ports   = []
    target_ip   = "N/A"
    if scan_nmap:
        hosts = scan_nmap.get('hosts', [])
        for h in hosts:
            all_ports.extend(h.get('ports', []))
        if hosts:
            target_ip = hosts[0].get('ip', 'N/A')
    total_ports  = len(all_ports)
    web_findings = len(scan_web.get('found_paths', [])) if scan_web else 0

    risk_score, nivel, nivel_color = _calcular_risk_score(scan_nmap, scan_web, ssl_data, email_data)
    _,          _nivel_old, _      = _calcular_risk_score(scan_nmap, scan_web, None, None)
    nivel_color_old = nivel_color  # keep for compat

    fecha_full = datetime.datetime.now().strftime("%d/%m/%Y  ·  %H:%M hrs")

    doc = SimpleDocTemplate(
        path, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=22*mm, bottomMargin=16*mm,
    )
    s = _styles()
    story = []

    # ═══ PORTADA ══════════════════════════════════════════════════════════════
    story.append(Spacer(1, 36*mm))
    story.append(Paragraph("INFORME DE AUDITORÍA DE SEGURIDAD", s['cover_label']))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph("Evaluación de<br/>Superficie de Ataque", s['cover_title']))
    story.append(Paragraph(
        f"Análisis de Riesgo y Vulnerabilidades  ·  {fecha_full}", s['cover_sub']))
    story.append(HRFlowable(width=FULL_W, thickness=1, color=ACCENT_CYAN, spaceAfter=7*mm))

    mv = ParagraphStyle('mv', fontName='Helvetica-Bold', fontSize=10, textColor=WHITE)
    ml = ParagraphStyle('ml', fontName='Helvetica', fontSize=8, textColor=TEXT_MUTED)

    meta_data = [
        [Paragraph("CLASIFICACIÓN", ml),
         Paragraph("HERRAMIENTA", ml),
         Paragraph("NIVEL DE RIESGO", ml),
         Paragraph("OBJETIVO", ml)],
        [Paragraph('<font color="#FF3B3B"><b>CONFIDENCIAL</b></font>', mv),
         Paragraph("Sentinel-Nmap", mv),
         Paragraph(f'<font color="#{nivel_color.hexval()[2:]}"><b>{nivel}</b></font>', mv),
         Paragraph(target_ip, mv)],
    ]
    meta_t = Table(meta_data, colWidths=[FULL_W / 4] * 4)
    meta_t.setStyle(TableStyle([
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LINEBELOW', (0, 0), (-1, 0), 0.3, BORDER_COLOR),
    ]))
    story.append(meta_t)
    story.append(Spacer(1, 14*mm))

    ssl_findings_count   = len(ssl_data.get('findings', []))   if ssl_data   else 0
    email_findings_count = len(email_data.get('findings', [])) if email_data else 0
    total_findings = (
        sum(1 for h in (scan_nmap or {}).get('hosts',[]) for _ in h.get('ports',[]))
        + web_findings + ssl_findings_count + email_findings_count
    )

    kpi_col = FULL_W / 5
    kpi_data = [[
        Paragraph(str(total_hosts), s['kpi_val']),
        Paragraph(str(total_ports), s['kpi_val']),
        Paragraph(str(web_findings + ssl_findings_count + email_findings_count), s['kpi_val']),
        Paragraph(str(risk_score),  s['kpi_val']),
        Paragraph(nivel, ParagraphStyle('kpir', fontName='Helvetica-Bold', fontSize=18,
                                         textColor=nivel_color, alignment=TA_CENTER)),
    ], [
        Paragraph("DISPOSITIVOS", s['kpi_lbl']),
        Paragraph("SERVICIOS EXPUESTOS", s['kpi_lbl']),
        Paragraph("HALLAZGOS TOTALES", s['kpi_lbl']),
        Paragraph("RISK SCORE", s['kpi_lbl']),
        Paragraph("NIVEL DE RIESGO", s['kpi_lbl']),
    ]]
    kpi_t = Table(kpi_data, colWidths=[kpi_col] * 5, rowHeights=[13*mm, 7*mm])
    kpi_t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), PANEL_BG),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('LINEAFTER', (0, 0), (2, 1), 0.5, BORDER_COLOR),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROUNDEDCORNERS', [6]),
    ]))
    story.append(kpi_t)
    story.append(Spacer(1, 8*mm))
    story.append(Paragraph(
        "Preparado por: <b>Sentinel-Core AI Systems</b>  ·  Equipo de Seguridad Ofensiva",
        s['cover_meta']))
    story.append(PageBreak())

    # ═══ 01  /  INVENTARIO TÉCNICO DE PUERTOS ═════════════════════════════════
    story.append(Paragraph("01  /  INVENTARIO TÉCNICO DE PUERTOS", s['sec_hdr']))
    story.append(HRFlowable(width=FULL_W, thickness=0.5, color=BORDER_COLOR, spaceAfter=4*mm))

    if scan_nmap and scan_nmap.get('hosts'):
        for host in scan_nmap['hosts']:
            ip  = host.get('ip', 'N/A')
            os_ = host.get('os_detected', 'Desconocido')

            story.append(Paragraph(
                f'<font color="#00D4FF"><b>HOST</b></font>  '
                f'<font color="#FFFFFF"><b>{ip}</b></font>  '
                f'<font color="#8B949E">|  Sistema Operativo: {os_}</font>',
                s['subsec']))

            ports = host.get('ports', [])
            if not ports:
                story.append(Paragraph("Sin puertos abiertos detectados en este host.",
                                       s['body_muted']))
                story.append(Spacer(1, 4*mm))
                continue

            col_w = [18*mm, 30*mm, FULL_W - 18*mm - 30*mm - 26*mm - 24*mm, 26*mm, 24*mm]
            rows = [[
                Paragraph(h, s['th'])
                for h in ["PUERTO", "SERVICIO", "VERSIÓN / PRODUCTO", "RIESGO", "ESTADO"]
            ]]
            for p in ports:
                pnum  = p.get('port', '?')
                psvc  = (p.get('service') or '').upper() or '—'
                label = _version_label(p)
                has_version = bool((p.get('product') or '').strip() or
                                   (p.get('version') or '').strip())
                risk_label, risk_col = _port_risk(pnum)
                rows.append([
                    Paragraph(f"<b>{pnum}</b>", s['tc']),
                    Paragraph(psvc, s['tc']),
                    Paragraph(label, s['tl'] if has_version else s['tl_muted']),
                    _badge(risk_label, risk_col, s, w=22*mm),
                    _badge("ABIERTO", ACCENT_GREEN, s, 'badge_d', w=20*mm),
                ])

            pt = Table(rows, colWidths=col_w)
            pt.setStyle(TableStyle(_BASE_TABLE_STYLE))
            story.append(pt)
            story.append(Spacer(1, 6*mm))
    else:
        story.append(Paragraph("No se recibieron datos de escaneo Nmap.", s['body_muted']))

    # ═══ 02  /  SUPERFICIE WEB ════════════════════════════════════════════════
    if scan_web and scan_web.get('found_paths'):
        story.append(Paragraph("02  /  ANÁLISIS DE SUPERFICIE WEB", s['sec_hdr']))
        story.append(HRFlowable(width=FULL_W, thickness=0.5, color=BORDER_COLOR, spaceAfter=4*mm))

        web_col = [FULL_W * 0.55, 26*mm, FULL_W - FULL_W * 0.55 - 26*mm]
        web_rows = [[
            Paragraph(h, s['th'])
            for h in ["DIRECTORIO / RUTA", "HTTP CODE", "EXPOSICIÓN"]
        ]]
        for p in scan_web['found_paths']:
            code = p.get('code', '?')
            exposed = (code == 200)
            lbl = "EXPUESTO" if exposed else "RESTRINGIDO"
            col = ACCENT_RED if exposed else ACCENT_AMBER
            web_rows.append([
                Paragraph(str(p.get('path', '/')), s['tl']),
                Paragraph(str(code), s['tc']),
                _badge(lbl, col, s, w=28*mm),
            ])
        wt = Table(web_rows, colWidths=web_col)
        wt.setStyle(TableStyle(_BASE_TABLE_STYLE))
        story.append(wt)
        story.append(Spacer(1, 4*mm))

    # ═══ 03  /  SSL/TLS ANALYSIS ══════════════════════════════════════════════
    if ssl_data and ssl_data.get('findings'):
        story.append(Paragraph("03  /  ANÁLISIS SSL/TLS", s['sec_hdr']))
        story.append(HRFlowable(width=FULL_W, thickness=0.5, color=BORDER_COLOR, spaceAfter=4*mm))

        cert = ssl_data.get('certificate', {})
        if cert.get('ok'):
            days    = cert.get('days_left', 0)
            d_color = ACCENT_RED if days < 30 else ACCENT_GREEN
            cert_rows = [
                [Paragraph(h, s['th']) for h in ["CAMPO", "VALOR"]],
                [Paragraph("Common Name (CN)", s['tl']),        Paragraph(cert.get('subject_cn','?'), s['tl'])],
                [Paragraph("Emisor",            s['tl']),        Paragraph(cert.get('issuer_o','?'), s['tl'])],
                [Paragraph("Expiración",        s['tl']),        Paragraph(f"{cert.get('expiry_date','?')} ({days} días)", s['tl'])],
                [Paragraph("Protocolo negociado", s['tl']),      Paragraph(cert.get('negotiated_protocol','?'), s['tl'])],
                [Paragraph("Self-signed",       s['tl']),        Paragraph("SÍ ⚠" if cert.get('self_signed') else "No", s['tl'])],
            ]
            ct = Table(cert_rows, colWidths=[FULL_W * 0.35, FULL_W * 0.65])
            ct.setStyle(TableStyle(_BASE_TABLE_STYLE))
            story.append(ct)
            story.append(Spacer(1, 4*mm))

        _sev_col_map = {'CRÍTICO': ACCENT_RED, 'ALTO': ACCENT_RED, 'MEDIO': ACCENT_AMBER, 'BAJO': TEXT_MUTED}
        ssl_rows = [[Paragraph(h, s['th']) for h in ["ID", "SEVERIDAD", "HALLAZGO", "REMEDIACIÓN"]]]
        for f in ssl_data['findings']:
            fc = _sev_col_map.get(f['severity'], TEXT_MUTED)
            ssl_rows.append([
                Paragraph(f['id'],          s['tc']),
                _badge(f['severity'], fc, s, w=20*mm),
                Paragraph(f['title'],       s['tl']),
                Paragraph(f['remediation'][:120], s['tl_muted']),
            ])
        ssl_t = Table(ssl_rows, colWidths=[18*mm, 22*mm, FULL_W*0.42, FULL_W*0.30])
        ssl_t.setStyle(TableStyle(_BASE_TABLE_STYLE))
        story.append(ssl_t)
        story.append(Spacer(1, 6*mm))

    # ═══ 04  /  EMAIL SECURITY ════════════════════════════════════════════════
    if email_data and email_data.get('findings'):
        story.append(Paragraph("04  /  SEGURIDAD DE EMAIL (SPF · DMARC · DKIM)", s['sec_hdr']))
        story.append(HRFlowable(width=FULL_W, thickness=0.5, color=BORDER_COLOR, spaceAfter=4*mm))

        spf_r   = email_data.get('spf',   {})
        dmarc_r = email_data.get('dmarc', {})
        dkim_r  = email_data.get('dkim',  {})

        _p = lambda ok: "✅  Configurado" if ok else "❌  Ausente"
        dns_rows = [
            [Paragraph(h, s['th']) for h in ["CONTROL", "ESTADO", "POLÍTICA / DETALLE"]],
            [Paragraph("SPF",   s['tl']), Paragraph(_p(spf_r.get('present')),   s['tl']),
             Paragraph(str(spf_r.get('record','—'))[:80],   s['tl_muted'])],
            [Paragraph("DMARC", s['tl']), Paragraph(_p(dmarc_r.get('present')), s['tl']),
             Paragraph(f"p={dmarc_r.get('policy','—')} — {dmarc_r.get('policy_desc','')[:70]}", s['tl_muted'])],
            [Paragraph("DKIM",  s['tl']), Paragraph(_p(dkim_r.get('present')),  s['tl']),
             Paragraph(", ".join(x['selector'] for x in dkim_r.get('selectors',[])) or "No detectado", s['tl_muted'])],
        ]
        dns_t = Table(dns_rows, colWidths=[22*mm, 35*mm, FULL_W - 22*mm - 35*mm])
        dns_t.setStyle(TableStyle(_BASE_TABLE_STYLE))
        story.append(dns_t)
        story.append(Spacer(1, 4*mm))

        _sev_col_map = {'CRÍTICO': ACCENT_RED, 'ALTO': ACCENT_RED, 'MEDIO': ACCENT_AMBER, 'BAJO': TEXT_MUTED}
        em_rows = [[Paragraph(h, s['th']) for h in ["ID", "SEVERIDAD", "HALLAZGO", "REMEDIACIÓN"]]]
        for f in email_data['findings']:
            fc = _sev_col_map.get(f['severity'], TEXT_MUTED)
            em_rows.append([
                Paragraph(f['id'],          s['tc']),
                _badge(f['severity'], fc, s, w=20*mm),
                Paragraph(f['title'],       s['tl']),
                Paragraph(f['remediation'][:120], s['tl_muted']),
            ])
        em_t = Table(em_rows, colWidths=[22*mm, 22*mm, FULL_W*0.42, FULL_W*0.30])
        em_t.setStyle(TableStyle(_BASE_TABLE_STYLE))
        story.append(em_t)
        story.append(Spacer(1, 6*mm))

    # ═══ 05  /  PRIORIZACIÓN ESTRATÉGICA ══════════════════════════════════════
    story.append(PageBreak())
    story.append(Paragraph("03  /  PRIORIZACIÓN ESTRATÉGICA", s['sec_hdr']))
    story.append(HRFlowable(width=FULL_W, thickness=0.5, color=BORDER_COLOR, spaceAfter=4*mm))

    def _prio_card(accent, label, timeframe, items_list):
        """Tarjeta vertical con label, tiempo y bullets. No se desborda."""
        hex_col = accent.hexval()[2:]
        bullets_html = "<br/>".join(
            f'<font color="#{hex_col}">■</font>&nbsp;&nbsp;{it}'
            for it in items_list
        )
        inner_rows = [
            [Paragraph(f'<font color="#{hex_col}">● {label}</font>', s['prio_label'])],
            [Paragraph(timeframe, s['prio_time'])],
            [HRFlowable(width=50*mm, thickness=0.5, color=accent, spaceAfter=1)],
            [Paragraph(bullets_html, s['prio_item'])],
        ]
        inner = Table(inner_rows, colWidths=[None])
        inner.setStyle(TableStyle([
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        return inner

    critico_items = [
        "Endurecer SSH: root login off",
        "Implementar claves RSA 4096-bit",
        "Activar fail2ban (umbral estricto)",
        "Restringir IPs en firewall",
        "Revisar puertos críticos 21/23/445",
    ]
    alto_items = [
        "Asegurar proxy HTTP (8080)",
        "Actualizar versiones de servicios",
        "Autenticación en servicios web",
        "Revisar rutas expuestas (200 OK)",
        "Segmentación de red mínima",
    ]
    continuo_items = [
        "Monitoreo 24/7 en SIEM",
        "Alertas de acceso no autorizado",
        "Escaneos periódicos de VM",
        "Revisión post-remediación",
        "Correlación de eventos en tiempo real",
    ]

    prio_col_w = (FULL_W - 4*mm) / 3
    prio_data = [[
        _prio_card(ACCENT_RED,   "CRÍTICO",  "< 24 HORAS",  critico_items),
        _prio_card(ACCENT_AMBER, "ALTO",     "< 7 DÍAS",    alto_items),
        _prio_card(ACCENT_CYAN,  "CONTINUO", "MONITOREO",   continuo_items),
    ]]
    prio_t = Table(prio_data, colWidths=[prio_col_w] * 3)
    prio_t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#2D1B1B")),
        ('BACKGROUND', (1, 0), (1, -1), colors.HexColor("#2D2200")),
        ('BACKGROUND', (2, 0), (2, -1), colors.HexColor("#0D1E2D")),
        ('BOX', (0, 0), (0, -1), 1, ACCENT_RED),
        ('BOX', (1, 0), (1, -1), 1, ACCENT_AMBER),
        ('BOX', (2, 0), (2, -1), 1, ACCENT_CYAN),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ROUNDEDCORNERS', [6]),
    ]))
    story.append(prio_t)
    story.append(Spacer(1, 8*mm))

    # ═══ 04  /  RESUMEN ESTRATÉGICO (IA / Gemini) ═════════════════════════════
    story.append(PageBreak())
    story.append(Paragraph("04  /  RESUMEN ESTRATÉGICO  (Cyber-Jarvis AI)", s['sec_hdr']))
    story.append(HRFlowable(width=FULL_W, thickness=0.5, color=BORDER_COLOR, spaceAfter=4*mm))

    alert = Table([[
        Paragraph("!", ParagraphStyle('ai', fontName='Helvetica-Bold', fontSize=18,
                                       textColor=nivel_color, alignment=TA_CENTER)),
        Paragraph(
            f"<b>NIVEL DE RIESGO GLOBAL:  "
            f'<font color="#{nivel_color.hexval()[2:]}">{nivel}</font></b><br/>'
            "<font color='#8B949E' size='8'>"
            "Análisis generado por IA. Revisar y validar con el equipo de SecOps "
            "antes de aplicar remediaciones en producción.</font>",
            ParagraphStyle('ab', fontName='Helvetica', fontSize=9,
                           textColor=WHITE, leading=14)),
    ]], colWidths=[12*mm, FULL_W - 12*mm])
    alert.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), PANEL_BG),
        ('BOX', (0, 0), (-1, -1), 1, nivel_color),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROUNDEDCORNERS', [4]),
    ]))
    story.append(alert)
    story.append(Spacer(1, 5*mm))

    story.extend(_markdown_to_flowables(ai_analysis, s))
    story.append(Spacer(1, 8*mm))

    # ═══ PIE DE FIRMA ═════════════════════════════════════════════════════════
    signoff = Table([[
        Paragraph(
            "<b>Sentinel-Core AI Systems</b><br/>"
            "<font color='#8B949E' size='8'>Equipo de Seguridad Ofensiva</font>",
            ParagraphStyle('sg', fontName='Helvetica', fontSize=9,
                           textColor=WHITE, leading=14)),
        Paragraph(
            f"<b>Emisión:</b>  {fecha_full}<br/>"
            "<b>Próxima revisión:</b>  7 días",
            ParagraphStyle('sg2', fontName='Helvetica', fontSize=8.5,
                           textColor=TEXT_MUTED, leading=14)),
        Paragraph(
            '<font color="#FF3B3B"><b>CONFIDENCIAL</b></font><br/>'
            '<font size="7" color="#8B949E">Uso Interno Exclusivo</font>',
            ParagraphStyle('sg3', fontName='Helvetica', fontSize=9, textColor=WHITE,
                           alignment=TA_RIGHT, leading=14)),
    ]], colWidths=[FULL_W * 0.35, FULL_W * 0.35, FULL_W * 0.30])
    signoff.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), PANEL_BG),
        ('BOX', (0, 0), (-1, -1), 0.5, ACCENT_CYAN),
        ('LINEABOVE', (0, 0), (-1, 0), 2, ACCENT_CYAN),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROUNDEDCORNERS', [4]),
    ]))
    story.append(signoff)

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return path


def limpiar_texto_markdown(texto: str) -> str:
    return texto or ""
