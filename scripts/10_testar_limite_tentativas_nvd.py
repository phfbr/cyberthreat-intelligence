
import ast
from pathlib import Path
from unittest.mock import Mock, patch

import requests
import time


# Localizar a função no coletor
caminho = Path("scripts/07_coletar_paginas_nvd.py")

arvore = ast.parse(
    caminho.read_text(encoding="utf-8")
)

funcao = next(
    no for no in arvore.body
    if isinstance(no, ast.FunctionDef)
    and no.name == "consultar_nvd"
)

modulo = ast.Module(
    body=[funcao],
    type_ignores=[]
)

ast.fix_missing_locations(modulo)


# Preparar ambiente de teste
ambiente = {
    "requests": requests,
    "time": time,
    "URL": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "HEADERS": {
        "User-Agent": "CyberThreatIntelligence-Learning/1.0"
    },
    "MAX_TENTATIVAS": 3,
    "INTERVALO": 6
}

exec(
    compile(modulo, str(caminho), "exec"),
    ambiente
)

consultar_nvd = ambiente["consultar_nvd"]


# Simular uma API indisponível
erro_503 = Mock()
erro_503.status_code = 503
erro_503.headers = {}

with patch.object(
    requests,
    "get",
    return_value=erro_503
) as requisicao_simulada:

    with patch.object(
        time,
        "sleep"
    ) as espera_simulada:

        try:
            consultar_nvd(
                {"resultsPerPage": 5, "startIndex": 0}
            )

        except RuntimeError as erro:
            mensagem_erro = str(erro)

        else:
            raise AssertionError(
                "O coletor deveria ter interrompido a consulta."
            )


# Validar o limite de tentativas
assert requisicao_simulada.call_count == 3

tempos = [
    chamada.args[0]
    for chamada in espera_simulada.call_args_list
]

assert tempos == [6, 12]

assert "3 tentativas" in mensagem_erro


print("\nRESULTADO DO TESTE")
print("Tentativas realizadas:", requisicao_simulada.call_count)
print("Intervalos de espera:", tempos)
print("Falha final identificada: SIM")
print("Limite de tentativas: OK")
