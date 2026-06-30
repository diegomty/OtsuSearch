@echo off
echo.
echo  ==========================================
echo    OtsuSearch -- Setup para Windows
echo  ==========================================
echo.

:: ── 1. Verificar Python ───────────────────────────────────────────────────
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python no encontrado.
    echo     Descarga Python 3.11+ desde: https://www.python.org/downloads/
    echo     Marca "Add Python to PATH" durante la instalacion.
    pause
    exit /b 1
)
echo [+] Python encontrado.

:: ── 2. Verificar Nmap ────────────────────────────────────────────────────
nmap --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [!] Nmap no encontrado.
    echo     1. Descarga desde: https://nmap.org/download.html
    echo     2. Marca "Add Nmap to PATH" durante la instalacion.
    echo     3. Reinicia esta ventana y vuelve a ejecutar setup.bat
    pause
    exit /b 1
)
echo [+] Nmap encontrado.

:: ── 3. Info sobre Npcap ───────────────────────────────────────────────────
echo.
echo [i] Npcap (para escaneo ARP):
if exist "C:\Windows\System32\Npcap\wpcap.dll" (
    echo     [+] Npcap encontrado.
) else (
    echo     [!] Npcap no detectado o sin modo WinPcap.
    echo         Descarga: https://npcap.com/
    echo         Activa "Install Npcap in WinPcap API-compatible Mode"
    echo         El escaneo ARP no funcionara hasta instalarlo.
)

:: ── 4. Crear entorno virtual ──────────────────────────────────────────────
echo.
if not exist "venv\" (
    echo [*] Creando entorno virtual...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [!] Error creando venv.
        pause
        exit /b 1
    )
    echo [+] Entorno virtual creado.
) else (
    echo [+] Entorno virtual ya existe.
)

:: ── 5. Instalar dependencias ──────────────────────────────────────────────
echo.
echo [*] Instalando dependencias Python...
venv\Scripts\pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo [!] Error en pip install.
    pause
    exit /b 1
)
echo [+] Dependencias instaladas.

:: ── 6. Copiar config de ejemplo ───────────────────────────────────────────
if not exist "data\config.json" (
    if exist "data\config.json.example" (
        copy "data\config.json.example" "data\config.json" >nul
        echo [+] data\config.json creado. Edita el archivo y agrega tu API Key.
    )
)

:: ── 7. Instrucciones finales ──────────────────────────────────────────────
echo.
echo  ==========================================
echo    Setup completado
echo  ==========================================
echo.
echo  Para iniciar OtsuSearch (como Administrador):
echo.
echo    venv\Scripts\python -m streamlit run app.py
echo.
echo  La app se abre en: http://localhost:8501
echo.
pause
