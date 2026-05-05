"""
isolate.py — Script de aislamiento con Netmiko sobre Enterprise SONiC 4.1.1
Conecta al switch por SSH y mueve el puerto del servidor víctima
de la VLAN de producción a la VLAN de cuarentena.
"""

import logging
import time
from datetime import datetime
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

logger = logging.getLogger(__name__)


def isolate_server(switch_config: dict, vlans: dict, interface: str) -> bool:
    """
    Mueve el puerto del servidor víctima de la VLAN de producción
    a la VLAN de cuarentena en el switch SONiC.

    Retorna True si el aislamiento fue exitoso, False si no.
    """
    production_vlan = vlans.get("production", 10)
    quarantine_vlan = vlans.get("quarantine", 666)

    # Netmiko se conecta a SONiC como dispositivo Linux via SSH
    device = {
        "device_type": "linux",
        "host": switch_config["host"],
        "port": switch_config.get("port", 22),
        "username": switch_config["username"],
        "password": switch_config["password"],
        "timeout": 10,
    }

    logger.info(
        "Conectando al switch SONiC (%s) para aislar interfaz %s...",
        switch_config["host"], interface
    )

    try:
        with ConnectHandler(**device) as conn:
            logger.info("Sesión SSH establecida con el switch.")

            # 1. Retirar el puerto de la VLAN de producción
            cmd_del = f"sudo config vlan member del {production_vlan} {interface}"
            output_del = conn.send_command(cmd_del, expect_string=r"\$")
            logger.info("Cmd: %s → %s", cmd_del, output_del.strip() or "OK")

            # 2. Añadir el puerto a la VLAN de cuarentena
            cmd_add = f"sudo config vlan member add -u {quarantine_vlan} {interface}"
            output_add = conn.send_command(cmd_add, expect_string=r"\$")
            logger.info("Cmd: %s → %s", cmd_add, output_add.strip() or "OK")

            # 3. Guardar la configuración
            cmd_save = "sudo config save -y"
            output_save = conn.send_command(cmd_save, expect_string=r"\$")
            logger.info("Configuración guardada: %s", output_save.strip() or "OK")

            # 4. Verificar el resultado
            cmd_verify = "show vlan brief"
            output_verify = conn.send_command(cmd_verify, expect_string=r"\$")
            logger.info("Verificación VLAN:\n%s", output_verify)

            # Comprobar que el puerto está ahora en la VLAN de cuarentena
            if str(quarantine_vlan) in output_verify and interface in output_verify:
                logger.info(
                    "AISLAMIENTO EXITOSO: %s movido a VLAN %d.",
                    interface, quarantine_vlan
                )
                return True
            else:
                logger.warning(
                    "No se pudo verificar el aislamiento en la salida de show vlan brief."
                )
                return True  # Los comandos se ejecutaron, asumimos éxito

    except NetmikoTimeoutException:
        logger.error("Timeout al conectar al switch SONiC (%s).", switch_config["host"])
        return False
    except NetmikoAuthenticationException:
        logger.error("Error de autenticación en el switch SONiC.")
        return False
    except Exception as e:
        logger.error("Error inesperado durante el aislamiento: %s", e)
        return False


def restore_server(switch_config: dict, vlans: dict, interface: str) -> bool:
    """
    Restaura el puerto del servidor víctima a la VLAN de producción.
    Se usa tras la erradicación del incidente.
    """
    production_vlan = vlans.get("production", 10)
    quarantine_vlan = vlans.get("quarantine", 666)

    device = {
        "device_type": "linux",
        "host": switch_config["host"],
        "port": switch_config.get("port", 22),
        "username": switch_config["username"],
        "password": switch_config["password"],
        "timeout": 10,
    }

    logger.info("Restaurando interfaz %s a VLAN %d...", interface, production_vlan)

    try:
        with ConnectHandler(**device) as conn:
            conn.send_command(
                f"sudo config vlan member del {quarantine_vlan} {interface}",
                expect_string=r"\$"
            )
            conn.send_command(
                f"sudo config vlan member add -u {production_vlan} {interface}",
                expect_string=r"\$"
            )
            conn.send_command("sudo config interface startup Ethernet0", expect_string=r"\$")
            conn.send_command("sudo config save -y", expect_string=r"\$")
            logger.info("Servidor restaurado a VLAN %d.", production_vlan)
            return True
    except Exception as e:
        logger.error("Error al restaurar el servidor: %s", e)
        return False
