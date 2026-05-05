"""
Tests unitarios para el MMR — Módulo de Monitorización de Red.
Ejecutar con: pytest tests/test_mmr.py -v
"""

import queue
import unittest
from unittest.mock import patch, MagicMock

from modules.mmr import MMR


CONFIG = {
    "check_interval": 1,
    "allowed_ports": [22, 443, 9999],
    "allowed_processes": ["sshd", "python3"],
}


def _make_conn(remote_ip, remote_port, pid, status="ESTABLISHED"):
    """Helper: crea una conexión simulada de psutil."""
    conn = MagicMock()
    conn.status = status
    conn.raddr = MagicMock()
    conn.raddr.ip = remote_ip
    conn.raddr.port = remote_port
    conn.pid = pid
    return conn


class TestMMR(unittest.TestCase):

    def setUp(self):
        self.alert_queue = queue.Queue()
        self.mmr = MMR(CONFIG, self.alert_queue)

    def test_conexion_permitida_no_genera_alerta(self):
        """Una conexión en puerto permitido por proceso permitido no genera alerta."""
        conn = _make_conn("192.168.1.1", 443, 1234)
        with patch("psutil.net_connections", return_value=[conn]):
            with patch.object(self.mmr, "_get_process_name", return_value="python3"):
                self.mmr._analyze_connections()
        self.assertTrue(self.alert_queue.empty())

    def test_reverse_shell_puerto_4444_genera_alerta_critica(self):
        """Una conexión al puerto 4444 debe generar una alerta CRÍTICO."""
        conn = _make_conn("10.0.0.99", 4444, 9999)
        with patch("psutil.net_connections", return_value=[conn]):
            with patch.object(self.mmr, "_get_process_name", return_value="bash"):
                self.mmr._analyze_connections()
        self.assertFalse(self.alert_queue.empty())
        alerta = self.alert_queue.get()
        self.assertEqual(alerta.severity, "CRÍTICO")
        self.assertIn("4444", alerta.description)

    def test_puerto_no_autorizado_genera_alerta_alto(self):
        """Una conexión a un puerto no en lista blanca genera alerta ALTO."""
        conn = _make_conn("1.2.3.4", 8080, 5555)
        with patch("psutil.net_connections", return_value=[conn]):
            with patch.object(self.mmr, "_get_process_name", return_value="curl"):
                self.mmr._analyze_connections()
        self.assertFalse(self.alert_queue.empty())
        alerta = self.alert_queue.get()
        self.assertEqual(alerta.severity, "ALTO")

    def test_no_alertas_duplicadas(self):
        """Una misma conexión no debe generar más de una alerta."""
        conn = _make_conn("10.0.0.99", 4444, 9999)
        with patch("psutil.net_connections", return_value=[conn]):
            with patch.object(self.mmr, "_get_process_name", return_value="bash"):
                self.mmr._analyze_connections()
                self.mmr._analyze_connections()  # Segundo ciclo — no debe duplicar
        self.assertEqual(self.alert_queue.qsize(), 1)


if __name__ == "__main__":
    unittest.main()
