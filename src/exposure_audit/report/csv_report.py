# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : csv_report.py
# Descricao   : CSV consolidado de exposicao de todos os hosts.
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
CSV consolidado (secao 23 da diretriz). Uma linha por servico.
"""

import csv
import io

from exposure_audit.pipeline import HostReport
from exposure_audit.report.text import bind_text, external_status

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

COLUMNS: tuple[str, ...] = (
    "hostname", "ip", "public_ip", "port", "protocol", "service", "local_status",
    "bind_address", "external_status", "protection", "reason",
)


def render_csv(reports: list[HostReport]) -> str:
    """
    Gera o CSV consolidado. Hosts com falha geram uma linha com
    ``protection=INDETERMINADO`` e o motivo da falha.

    :param reports: list[HostReport]
    :return: str
    """
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    for report in reports:
        base = {"hostname": report.hostname or report.name, "ip": report.primary_ip or "",
                "public_ip": ";".join(report.public_ips)}
        if report.error:
            writer.writerow({**base, "port": "", "protocol": "", "service": "",
                             "local_status": report.status, "bind_address": "",
                             "external_status": "", "protection": "INDETERMINADO",
                             "reason": report.error})
            continue
        for svc in report.services:
            if svc.kind == "external-only":
                local = "SEM_LISTENER"
            else:
                local = "ATIVO" if svc.local_active else "DNAT"
            writer.writerow({**base, "port": svc.port, "protocol": svc.protocol,
                             "service": svc.service, "local_status": local,
                             "bind_address": bind_text(svc),
                             "external_status": external_status(svc),
                             "protection": svc.classification.value, "reason": svc.reason})
    return buffer.getvalue()
