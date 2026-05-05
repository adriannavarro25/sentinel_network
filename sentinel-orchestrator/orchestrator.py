"""
Sentinel-Network — Orquestador
Receptor de alertas del Agente Sentinel.
Escucha en el puerto configurado, procesa las alertas recibidas
y ejecuta el aislamiento automático ante alertas CRÍTICAS.
"""

import json
import logging
import socket
import sys
import time
from datetime import datetime

import yaml

from isolate import isolate_server

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/sentinel-orchestrator.log"),
    ],
)
logger = logging.getLogger("orchestrator")


def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def handle_alert(data: bytes, config: dict, last_isolation: dict) -> None:
    """
    Procesa una alerta recibida del agente.
    Si la severidad es CRÍTICO activa el aislamiento via Netmiko.
    Implementa rate limiting para evitar activaciones repetidas.
    """
    try:
        alert = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError:
        logger.warning("Mensaje recibido no es JSON válido: %s", data[:100])
        return

    severity  = alert.get("severity", "DESCONOCIDO")
    source    = alert.get("source", "?")
    desc      = alert.get("description", "")
    timestamp = alert.get("timestamp", datetime.utcnow().isoformat())

    logger.info(
        "ALERTA recibida [%s] de %s — %s: %s",
        severity, source, timestamp, desc
    )

    if severity != "CRÍTICO":
        logger.info("Severidad %s — sin acción autónoma.", severity)
        return

    # Rate limiting
    rate_limit = config.get("rate_limit_seconds", 30)
    last_time  = last_isolation.get("timestamp", 0)
    now        = time.time()

    if now - last_time < rate_limit:
        logger.warning(
            "Rate limit activo: aislamiento ejecutado hace %.1fs. Ignorando.",
            now - last_time
        )
        return

    logger.info("Alerta CRÍTICA confirmada. Iniciando aislamiento autónomo...")

    success = isolate_server(
        switch_config=config["switch"],
        vlans=config["vlans"],
        interface=config["victim_interface"],
    )

    if success:
        last_isolation["timestamp"] = now
        logger.info("=== AISLAMIENTO COMPLETADO. Servidor en VLAN de cuarentena. ===")
    else:
        logger.error("=== FALLO EN EL AISLAMIENTO. Intervención manual requerida. ===")


def main():
    config = load_config()
    host   = config["listen"]["host"]
    port   = config["listen"]["port"]

    # Registro del último aislamiento para rate limiting
    last_isolation = {"timestamp": 0}

    logger.info("=== Sentinel-Network Orquestador arrancando ===")
    logger.info("Escuchando alertas en %s:%d...", host, port)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)

        while True:
            try:
                conn, addr = srv.accept()
                with conn:
                    logger.info("Conexión recibida desde %s:%d", addr[0], addr[1])
                    data = b""
                    while chunk := conn.recv(4096):
                        data += chunk
                    if data:
                        handle_alert(data, config, last_isolation)
            except KeyboardInterrupt:
                logger.info("Orquestador detenido manualmente.")
                break
            except Exception as e:
                logger.error("Error en el bucle principal: %s", e)


if __name__ == "__main__":
    main()
