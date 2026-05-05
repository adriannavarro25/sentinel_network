"""
MVI — Módulo de Vigilancia de Integridad
Monitoriza periódicamente que los archivos críticos mantienen
el atributo de inmutabilidad (chattr +i) activo.
"""

import subprocess
import logging
import time
import threading
from datetime import datetime

logger = logging.getLogger(__name__)


class AlertEvent:
    """Representa un evento de alerta generado por cualquier módulo."""

    def __init__(self, source: str, severity: str, description: str):
        self.source = source
        self.severity = severity
        self.description = description
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "severity": self.severity,
            "description": self.description,
            "timestamp": self.timestamp,
        }


class MVI(threading.Thread):
    """
    Módulo de Vigilancia de Integridad.

    Verifica periódicamente que los archivos de la lista de monitorización
    mantienen el atributo de inmutabilidad activo. Si detecta que el
    atributo 'i' ha desaparecido de algún archivo, genera una alerta CRÍTICA
    y la coloca en la cola compartida con el MCA.
    """

    def __init__(self, config: dict, alert_queue):
        super().__init__(daemon=True, name="MVI")
        self.monitored_files = config.get("monitored_files", [])
        self.interval = config.get("check_interval", 10)
        self.alert_queue = alert_queue
        self._stop_event = threading.Event()

    def _check_immutability(self, filepath: str) -> bool:
        """
        Comprueba si un archivo tiene el atributo de inmutabilidad activo.
        Retorna True si el atributo 'i' está presente, False si no.
        """
        try:
            result = subprocess.run(
                ["lsattr", filepath],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                logger.warning("lsattr error en %s: %s", filepath, result.stderr.strip())
                return True  # No alertamos por errores de lsattr

            # La salida de lsattr tiene formato: "----i--------e-- /ruta/archivo"
            attrs = result.stdout.split()[0] if result.stdout.strip() else ""
            return "i" in attrs

        except FileNotFoundError:
            logger.error("lsattr no encontrado en el sistema.")
            return True
        except Exception as e:
            logger.error("Error inesperado comprobando %s: %s", filepath, e)
            return True

    def run(self):
        """Bucle principal de monitorización."""
        logger.info("MVI iniciado. Monitorizando %d archivos cada %ds.",
                    len(self.monitored_files), self.interval)

        while not self._stop_event.is_set():
            for filepath in self.monitored_files:
                if not self._check_immutability(filepath):
                    logger.critical("ALERTA: atributo de inmutabilidad ausente en %s", filepath)
                    alert = AlertEvent(
                        source="MVI",
                        severity="CRÍTICO",
                        description=f"Atributo de inmutabilidad eliminado en {filepath}. "
                                    f"Posible intento de modificación del sistema.",
                    )
                    self.alert_queue.put(alert)
                else:
                    logger.debug("OK: %s mantiene atributo de inmutabilidad.", filepath)

            self._stop_event.wait(self.interval)

    def stop(self):
        self._stop_event.set()
