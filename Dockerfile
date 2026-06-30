FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    nmap \
    iproute2 \
    libpcap-dev \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 1. Aplicamos setcap al binario real de Python (Esto ya lo tenías bien)
RUN setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))

EXPOSE 8501

# 2. CAMBIO CLAVE: Ejecutamos Streamlit como un módulo de Python.
# Al usar "python3 -m streamlit", nos aseguramos de que se use el binario 
# que tiene los permisos de red (setcap) que configuramos arriba.
CMD ["python3", "-m", "streamlit", "run", "app.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true"]
