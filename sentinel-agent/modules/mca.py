"""
MCA — Módulo de Comunicación de Alertas
Transmite de forma segura los eventos de alerta generados por MVI y MMR
hacia el Orquestador mediante sockets TCP.
"""

import json
import logging
import socket
import threading
import time

logger = logging.getLogger(__name__)

TIMEOUT = 5       # segundos de timeout por intento de envío
MAX_RETRIES = 3   # reintentos antes de descartar la alerta


class MCA(threading.Thread):
    """
    Módulo de Comunicación de Alertas.

    Consume la cola de alertas compartida con MVI y MMR.
    Por cada alerta recibida, serializa el mensaje a JSON
    y lo envía al Orquestador mediante un socket TCP.
    Implementa reintentos automáticos en caso de fallo de red.

    NOTA: Para un entorno de producción real se añadiría TLS con
    ssl.wrap_socket y verificación de certificado del Orquestador.
    En este laboratorio se usa TCP plano para simplificar el despliegue.
    """

    def __init__(self, config: dict, alert_queue):
        super().__init__(daemon=True, name="MCA")
        orc = config.get("orchestrator", {})
        self.host = orc.get("host", "10.10.10.20")
        self.port = orc.get("port", 9999)
        self.alert_queue = alert_queue
        self._stop_event = threading.Event()

    def _send_alert(self, alert) -> bool:
        """
        Intenta enviar una alerta al Orquestador.
        Retorna True si el envío fue exitoso, False si no.
        """
        payload = json.dumps(alert.to_dict()).encode("utf-8")

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                with socket.create_connection((self.host, self.port), timeout=TIMEOUT) as sock:
                    sock.sendall(payload)
                    logger.info("Alerta enviada al Orquestador (%s:%d) — intento %d.",
                                self.host, self.port, attempt)
                    return True
            except (ConnectionRefusedError, socket.timeout, OSError) as e:
                logger.warning("Intento %d/%d fallido al enviar alerta: %s",
                               attempt, MAX_RETRIES, e)
                if attempt < MAX_RETRIES:
                    time.sleep(2)

        logger.error("No se pudo enviar la alerta tras %d intentos. Descartada.", MAX_RETRIES)
        return False

    def run(self):
        """Bucle principal: consume la cola y envía alertas."""
        logger.info("MCA iniciado. Enviando alertas a %s:%d.", self.host, self.port)

        while not self._stop_event.is_set():
            try:
                # Bloquea hasta que haya una alerta en la cola (timeout 1s)
                alert = self.alert_queue.get(timeout=1)
                logger.info("Procesando alerta [%s] de %s: %s",
                            alert.severity, alert.source, alert.description)
                self._send_alert(alert)
                self.alert_queue.task_done()
            except Exception:
                # Queue.get timeout — seguimos esperando
                continue

    def stop(self):
        self._stop_event.set()
