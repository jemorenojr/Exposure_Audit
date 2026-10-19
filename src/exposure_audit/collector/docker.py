# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : docker.py
# Descricao   : Parser de ``docker inspect`` para identificar portas
#               publicadas por containers.
# Author      : Jose Edson Moreno Jr.
# Email       : edson.moreno@gmail.com
# Versao      : 0.1
# Data        : 2026-10-19
# copyright   : (c) 2026 by Edson Moreno
# Parametros  :
# Opcoes      :
#
# Retorno     :
#
# CHANGELOG   :
#
############################################################################

"""
Publicacoes Docker.

As publicacoes sao evidencia complementar: a exposicao efetiva de uma
porta publicada e avaliada pelo caminho DNAT + FORWARD (chains DOCKER,
DOCKER-USER), e nao pela chain INPUT.
"""

import json

from exposure_audit.models import DockerPublication

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"


def _container_ips(network_settings: dict[str, object]) -> list[str]:
    """
    Extrai os IPs do container em todas as redes.

    :param network_settings: dict[str, object]
    :return: list[str]
    """
    ips: list[str] = []
    networks = network_settings.get("Networks") or {}
    if isinstance(networks, dict):
        for net in networks.values():
            if isinstance(net, dict):
                for key in ("IPAddress", "GlobalIPv6Address"):
                    value = net.get(key)
                    if value:
                        ips.append(str(value))
    return ips


def parse_docker_inspect(output: str) -> list[DockerPublication]:
    """
    Interpreta a saida JSON de ``docker inspect``.

    :param output: str
    :return: list[DockerPublication]
    """
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    publications: list[DockerPublication] = []
    for container in data if isinstance(data, list) else []:
        name = str(container.get("Name", "")).lstrip("/")
        cid = str(container.get("Id", ""))[:12]
        settings = container.get("NetworkSettings") or {}
        ips = _container_ips(settings)
        ports = settings.get("Ports") or {}
        for spec, bindings in ports.items():
            port_text, _, protocol = spec.partition("/")
            if not bindings or not port_text.isdigit():
                continue
            for binding in bindings:
                host_port = str(binding.get("HostPort", ""))
                if not host_port.isdigit():
                    continue
                publications.append(DockerPublication(
                    container=name, container_id=cid, protocol=protocol or "tcp",
                    host_ip=str(binding.get("HostIp") or "0.0.0.0"),
                    host_port=int(host_port), container_port=int(port_text),
                    container_ips=ips,
                ))
    return publications
