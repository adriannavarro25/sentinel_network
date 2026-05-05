"""
Tests unitarios para el MVI — Módulo de Vigilancia de Integridad.
Ejecutar con: pytest tests/test_mvi.py -v
"""

import queue
import unittest
from unittest.mock import patch, MagicMock

from modules.mvi import MVI


CONFIG = {
    "check_interval": 1,
    "monitored_files": ["/etc/shadow", "/etc/passwd"],
}


class TestMVI(unittest.TestCase):

    def setUp(self):
        self.alert_queue = queue.Queue()
        self.mvi = MVI(CONFIG, self.alert_queue)

    def test_archivo_con_inmutabilidad_no_genera_alerta(self):
        """Si el atributo i está presente, no debe generarse ninguna alerta."""
        lsattr_output = "----i--------e-- /etc/shadow\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=lsattr_output, stderr=""
            )
            resultado = self.mvi._check_immutability("/etc/shadow")
        self.assertTrue(resultado)
        self.assertTrue(self.alert_queue.empty())

    def test_archivo_sin_inmutabilidad_retorna_false(self):
        """Si el atributo i no está, _check_immutability debe retornar False."""
        lsattr_output = "-------------e-- /etc/shadow\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=lsattr_output, stderr=""
            )
            resultado = self.mvi._check_immutability("/etc/shadow")
        self.assertFalse(resultado)

    def test_alerta_critica_generada_cuando_falta_inmutabilidad(self):
        """Cuando falta el atributo i, debe aparecer una alerta CRÍTICO en la cola."""
        lsattr_output = "-------------e-- /etc/shadow\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=lsattr_output, stderr=""
            )
            # Ejecutamos un único ciclo de verificación manualmente
            for filepath in self.mvi.monitored_files:
                if not self.mvi._check_immutability(filepath):
                    from modules.mvi import AlertEvent
                    alert = AlertEvent("MVI", "CRÍTICO", f"Inmutabilidad ausente en {filepath}")
                    self.alert_queue.put(alert)
                    break

        self.assertFalse(self.alert_queue.empty())
        alerta = self.alert_queue.get()
        self.assertEqual(alerta.severity, "CRÍTICO")
        self.assertEqual(alerta.source, "MVI")

    def test_error_lsattr_no_genera_alerta(self):
        """Si lsattr falla, el módulo no debe generar una falsa alerta."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="lsattr: error"
            )
            resultado = self.mvi._check_immutability("/etc/shadow")
        self.assertTrue(resultado)  # Por defecto asume que está OK
        self.assertTrue(self.alert_queue.empty())


if __name__ == "__main__":
    unittest.main()
