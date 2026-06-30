#!/bin/bash

# --- 0. Forzar privilegios de Root ---
if [ "$EUID" -ne 0 ]; then
  echo "🔐 Sentinel necesita privilegios de administrador para configurar la red."
  sudo "$0" "$@"
  exit
fi

echo "🚀 Sentinel-Core-AI | Advanced Setup"

# --- 1. Verificar Docker ---
if ! command -v docker &> /dev/null
then
    echo "📦 Instalando Docker y dependencias de red..."
    curl -fsSL https://get.docker.com | sh
    apt update && apt install -y docker-compose libpcap-dev
    systemctl enable --now docker
else
    echo "✅ Docker ya está instalado"
fi

# --- 2. Configurar .env ---
if [ ! -f ".env" ]; then
    echo "🔐 Configurando variables de entorno..."
    cp .env.example .env 2>/dev/null || touch .env
    
    # Si no hay terminal interactiva, puedes hardcodear o pedir
    read -p "👉 Ingresa tu GEMINI API KEY: " API_KEY
    echo "GEMINI_KEY=$API_KEY" > .env
    echo "✅ API Key configurada en .env"
else
    echo "✅ Archivo .env ya existe"
fi

# --- 3. El "Toque de Poder" (Permisos de Red) ---
# Esto asegura que el usuario actual pueda usar docker sin sudo en el futuro
USER_NAME=${SUDO_USER:-$USER}
usermod -aG docker $USER_NAME
echo "✅ Usuario $USER_NAME añadido al grupo docker"

# --- 4. Levantar proyecto ---
echo "⚙️ Construyendo Sentinel-Core con privilegios de red..."
# Usamos --build para asegurar que cualquier cambio en los requisitos se aplique
docker-compose up -d --build

echo ""
echo "📊 Estado de la Suite Sentinel:"
docker ps

echo ""
echo "🌐 Sentinel-Core listo en: http://localhost:8501"
echo "⚠️ NOTA: Si es la primera vez que añades el usuario a docker, podrías necesitar reiniciar sesión para aplicar grupos."