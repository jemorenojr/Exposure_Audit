# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : __main__.py
# Descricao   : Permite executar ``python -m exposure_audit``.
# Author      : Jose Edson Moreno Jr.
# Email       : edson.moreno@gmail.com
# Versao      : 0.1
# Data        : 2026-10-19
# copyright   : (c) 2026 by Edson Moreno
# Parametros  : os mesmos de ``exposure-audit``
# Opcoes      :
#
# Retorno     : codigo de saida da CLI
#
# CHANGELOG   :
#
############################################################################

"""
Execucao como modulo: ``python -m exposure_audit``.
"""

import sys

from exposure_audit.main import main

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

if __name__ == "__main__":
    sys.exit(main())
