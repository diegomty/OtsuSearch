import json
import os

CONFIG_PATH = "data/config.json"

_DEFAULTS = {
    "gemini_key":        "",
    "model":             "gemini-2.5-flash",
    "temperature":       0.3,
    "default_interface": "",        # vacío = Scapy auto-detecta
    "excluded_ips":      "192.168.1.1, 192.168.1.254",
    "debug_mode":        False,
}

def save_config(config_data):
    os.makedirs("data", exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(config_data, f, indent=4)

def load_config():
    config = dict(_DEFAULTS)

    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            config.update(json.load(f))

    # Variable de entorno siempre tiene precedencia sobre el archivo
    env_key = os.environ.get("GEMINI_KEY", "").strip()
    if env_key:
        config["gemini_key"] = env_key

    return config
