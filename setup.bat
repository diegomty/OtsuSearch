@echo off
setlocal enabledelayedexpansion
title OtsuSearch — Setup Windows

echo.
echo  ==========================================
echo    OtsuSearch — Setup para Windows
echo  ==========================================
echo.

:: ── 1. Verificar Python ───────────────────────────────────────────────────
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python no encontrado.
    echo     Descarga Python 3.11+ desde: https://www.python.org/downloads/
    echo     Asegurate de marcar "Add Python to PATH" durante la instalacion.
    pause & exit /b 1
)
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PY_VER=%%i
echo [+] Python %PY_VER% encontrado.

:: ── 2. Verificar Nmap ────────────────────────────────────────────────────
nmap --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [!] Nmap no encontrado.
    echo     1. Descarga desde: https://nmap.org/download.html
    echo     2. Durante la instalacion, marca "Add Nmap to PATH"
    echo     3. Reinicia esta ventana y vuelve a ejecutar setup.bat
    echo.
    pause & exit /b 1
)
echo [+] Nmap encontrado.

:: ── 3. Verificar Npcap (para Scapy ARP) ──────────────────────────────────
if exist "C:\Windows\System32\Npcap\wpcap.dll" (
    echo [+] Npcap encontrado.
) else (
    echo.
    echo [!] Npcap no encontrado (necesario para el modulo ARP/Scapy).
    echo     1. Descarga desde: https://npcap.com/
    echo     2. Durante la instalacion, activa "WinPcap API-compatible Mode"
    echo     3. Reinicia el PC despues de instalar Npcap
    echo.
    echo     Puedes continuar sin Npcap, pero el escaner ARP no funcionara.
    echo     Los modulos Nmap, SSL, Email y Web funcionan sin Npcap.
    echo.
    set /p CONT="Continuar sin Npcap? (s/n): "
    if /i "!CONT!" neq "s" ( pause & exit /b 1 )
)

:: ── 4. Crear entorno virtual ──────────────────────────────────────────────
if not exist "venv\" (
    echo.
    echo [*] Creando entorno virtual...
    python -m venv venv
    if %errorlevel% neq 0 ( echo [!] Error creando venv. & pause & exit /b 1 )
    echo [+] Entorno virtual creado.
) else (
    echo [+] Entorno virtual existente encontrado.
)

:: ── 5. Instalar dependencias ──────────────────────────────────────────────
echo.
echo [*] Instalando dependencias Python...
venv\Scripts\pip install -r requirements.txt --quiet
if %errorlevel% neq 0 ( echo [!] Error en pip install. & pause & exit /b 1 )
echo [+] Dependencias instaladas.

:: ── 6. Copiar config de ejemplo ───────────────────────────────────────────
if not exist "data\config.json" (
    if exist "data\config.json.example" (
        copy "data\config.json.example" "data\config.json" >nul
        echo [+] data\config.json creado desde el ejemplo.
        echo     Edita data\config.json y agrega tu API Key de Gemini o Claude.
    )
)

:: ── 7. Instrucciones finales ──────────────────────────────────────────────
echo.
echo  ==========================================
echo    Setup completado
echo  ==========================================
echo.
echo  Para iniciar OtsuSearch:
echo.
echo    venv\Scripts\python -m streamlit run app.py
echo.
echo  IMPORTANTE:
echo    - Ejecuta el terminal como Administrador para Nmap y Scapy
echo    - La app se abre en http://localhost:8501
echo    - Agrega tu API Key en Settings antes de usar el analisis IA
echo.
pause
