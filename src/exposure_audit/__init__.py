# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : __init__.py
# Descricao   : Pacote principal do Exposure Audit (auditoria de exposicao
#               de servicos em hosts Linux).
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
Exposure Audit: correlaciona estado local do host, firewall efetivo e
validacao externa para classificar a exposicao de cada servico.

Componentes logicos:

* ``collector``  -- visao interna do host (somente leitura);
* ``scanner``    -- visao externa real;
* ``correlator`` -- classificacao deterministica e justificada.
"""

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"
