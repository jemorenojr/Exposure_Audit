# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : json_report.py
# Descricao   : JSON bruto por host (evidencias + dados normalizados +
#               resultado do correlator).
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
JSON por host (secoes 24 e 25 da diretriz).

Nome do modulo ``json_report`` (e nao ``json``) para evitar confusao com
o modulo ``json`` da biblioteca padrao.
"""

import json
from datetime import datetime, timezone

from exposure_audit import __version__ as package_version
from exposure_audit.models import to_dict
from exposure_audit.pipeline import HostReport

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

SCHEMA_VERSION = "1"


def host_document(report: HostReport) -> dict[str, object]:
    """
    Monta o documento JSON de um host.

    :param report: HostReport
    :return: dict[str, object]
    """
    normalized = report.normalized
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": package_version,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "name": report.name,
        "target": report.target,
        "status": report.status,
        "error": report.error,
        "hostname": report.hostname,
        "addresses": normalized.get("addresses", []),
        "routing": normalized.get("routing", {}),
        "listeners": normalized.get("listeners", []),
        "firewall": normalized.get("firewall", {}),
        "nat": normalized.get("nat", []),
        "docker": normalized.get("docker", []),
        "external_scan": report.external,
        "context": to_dict(report.context) if report.context else None,
        "services": [_service(svc) for svc in report.services],
        "issues": report.issues,
        "raw": report.raw,
    }


def _service(svc: object) -> dict[str, object]:
    """
    Serializa um ServiceAssessment no formato de servico normalizado.

    :param svc: object
    :return: dict[str, object]
    """
    data = to_dict(svc)
    families = data.get("families", [])
    data["bind"] = [addr for fam in families for addr in fam.get("bind_addresses", [])]
    data["firewall_access"] = {fam["family"]: fam["firewall"]["access"] for fam in families}
    data["external_state"] = {fam["family"]: fam["external"]["state"] for fam in families}
    return data


def render_json(report: HostReport) -> str:
    """
    Serializa o documento JSON do host.

    :param report: HostReport
    :return: str
    """
    return json.dumps(host_document(report), indent=2, ensure_ascii=False, sort_keys=False)
