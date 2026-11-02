
import ast
import time
from pathlib import Path
from unittest.mock import Mock, patch

import requests


# ==========================================
# CARREGAR APENAS A FUNÇÃO DE CONSULTA
# ==========================================

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


# ==========================================
# SIMULAR RESPOSTAS DA API
# ==========================================

erro_429 = Mock()
erro_429.status_code = 429
erro_429.headers = {"Retry-After": "20"}

sucesso_200 = Mock()
sucesso_200.status_code = 200
sucesso_200.headers = {}
sucesso_200.raise_for_status.return_value = None


# ==========================================
# EXECUTAR O TESTE
# ==========================================

with patch.object(
    requests,
    "get",
    side_effect=[erro_429, sucesso_200]
) as requisicao_simulada:

    with patch.object(
        time,
        "sleep"
    ) as espera_simulada:

        resposta = consultar_nvd(
            {"resultsPerPage": 5, "startIndex": 0}
        )


# ==========================================
# VALIDAR O RESULTADO
# ==========================================

tempos = [
    chamada.args[0]
    for chamada in espera_simulada.call_args_list
]

assert resposta.status_code == 200
assert requisicao_simulada.call_count == 2
assert tempos == [20], (
    f"Tempo de espera inesperado: {tempos}"
)

print("\nRESULTADO DO TESTE")
print("Chamadas HTTP simuladas:", requisicao_simulada.call_count)
print("Tempo de espera:", tempos)
print("Resposta final:", resposta.status_code)
print("Tratamento de HTTP 429: OK")
