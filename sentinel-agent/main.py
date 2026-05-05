"""
Sentinel-Network — Agente Sentinel
Punto de entrada principal. Carga la configuración, inicializa
los tres módulos concurrentes y supervisa su ejecución.
"""

import logging
import queue
import signal
import sys
import time

import yaml

from modules.mvi import MVI
from modules.mmr import MMR
from modules.mca import MCA

# ── Configuración del logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/sentinel-agent.log"),
    ],
)
logger = logging.getLogger("main")


def load_config(path: str = "config.yaml") -> dict:
    """Carga la configuración desde el archivo YAML."""
    try:
        with open(path, "r") as f:
            config = yaml.safe_load(f)
            logger.info("Configuración cargada desde %s.", path)
            return config
    except FileNotFoundError:
        logger.error("Archivo de configuración no encontrado: %s", path)
        sys.exit(1)
    except yaml.YAMLError as e:
        logger.error("Error al parsear la configuración: %s", e)
        sys.exit(1)


def main():
    logger.info("=== Sentinel-Network Agent arrancando ===")

    config = load_config()

    # Cola compartida entre MVI/MMR (productores) y MCA (consumidor)
    alert_queue = queue.Queue()

    # Inicializar los tres módulos
    mvi = MVI(config, alert_queue)
    mmr = MMR(config, alert_queue)
    mca = MCA(config, alert_queue)

    modules = [mvi, mmr, mca]

    # Manejador de señales para apagado limpio
    def shutdown(signum, frame):
        logger.info("Señal de apagado recibida. Deteniendo módulos...")
        for m in modules:
            m.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # Arrancar los tres módulos como hilos daemon
    for m in modules:
        m.start()
        logger.info("Módulo %s iniciado.", m.name)

    logger.info("Todos los módulos activos. Agente en funcionamiento.")

    # Bucle de supervisión: reinicia módulos caídos
    while True:
        for m in modules:
            if not m.is_alive():
                logger.error("Módulo %s ha terminado inesperadamente. Reiniciando...", m.name)
                nuevo = m.__class__(config, alert_queue)
                modules[modules.index(m)] = nuevo
                nuevo.start()
        time.sleep(5)


if __name__ == "__main__":
    main()
