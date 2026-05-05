"""
MMR — Módulo de Monitorización de Red
Detecta conexiones de red anómalas, especialmente Reverse Shells,
comparando las conexiones activas contra una lista blanca.
"""

import logging
import threading
import psutil
from modules.mvi import AlertEvent

logger = logging.getLogger(__name__)

# Puertos clásicos de Reverse Shell conocidos
REVERSE_SHELL_PORTS = {4444, 4445, 1234, 5555, 6666, 7777, 8888, 9001}


class MMR(threading.Thread):
    """
    Módulo de Monitorización de Red.

    Analiza periódicamente las conexiones TCP activas del sistema.
    Cualquier conexión ESTABLISHED hacia un puerto no autorizado
    originada por un proceso no reconocido genera una alerta CRÍTICA.
    """

    def __init__(self, config: dict, alert_queue):
        super().__init__(daemon=True, name="MMR")
        self.allowed_ports = set(config.get("allowed_ports", []))
        self.allowed_processes = set(config.get("allowed_processes", []))
        self.interval = config.get("check_interval", 10)
        self.alert_queue = alert_queue
        self._stop_event = threading.Event()
        # Conjunto de conexiones ya alertadas para no generar duplicados
        self._alerted = set()

    def _get_process_name(self, pid: int) -> str:
        """Obtiene el nombre del proceso por PID."""
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "desconocido"

    def _analyze_connections(self):
        """Analiza las conexiones activas y genera alertas si procede."""
        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            logger.warning("Acceso denegado al leer conexiones de red. ¿Se ejecuta como root?")
            return

        for conn in connections:
            # Solo conexiones TCP establecidas con destino remoto
            if conn.status != "ESTABLISHED" or not conn.raddr:
                continue

            remote_port = conn.raddr.port
            remote_ip = conn.raddr.ip
            pid = conn.pid or 0
            process_name = self._get_process_name(pid)

            # Clave única para evitar alertas duplicadas
            conn_key = (remote_ip, remote_port, pid)

            # Comprobar si el puerto es de Reverse Shell conocido
            is_revshell = remote_port in REVERSE_SHELL_PORTS

            # Comprobar si el puerto está en la lista blanca
            is_allowed_port = remote_port in self.allowed_ports

            # Comprobar si el proceso está permitido
            is_allowed_process = process_name in self.allowed_processes

            if (is_revshell or not is_allowed_port) and not is_allowed_process:
                if conn_key not in self._alerted:
                    self._alerted.add(conn_key)
                    severity = "CRÍTICO" if is_revshell else "ALTO"
                    description = (
                        f"Conexión {'de Reverse Shell ' if is_revshell else ''}no autorizada "
                        f"detectada: {remote_ip}:{remote_port} "
                        f"(proceso: {process_name}, PID: {pid})"
                    )
                    logger.critical("ALERTA %s: %s", severity, description)
                    alert = AlertEvent(
                        source="MMR",
                        severity=severity,
                        description=description,
                    )
                    self.alert_queue.put(alert)

        # Limpiar alertas de conexiones que ya no existen
        active_keys = {
            (c.raddr.ip, c.raddr.port, c.pid or 0)
            for c in connections
            if c.status == "ESTABLISHED" and c.raddr
        }
        self._alerted &= active_keys

    def run(self):
        """Bucle principal de monitorización."""
        logger.info("MMR iniciado. Monitorizando conexiones de red cada %ds.", self.interval)

        while not self._stop_event.is_set():
            self._analyze_connections()
            self._stop_event.wait(self.interval)

    def stop(self):
        self._stop_event.set()
