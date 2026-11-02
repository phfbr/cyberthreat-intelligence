
import ast
from pathlib import Path
from unittest.mock import Mock, patch

# Caminho do coletor que queremos testar
caminho_coletor = Path(
    "scripts/07_coletar_paginas_nvd.py"
)

# Ler o código sem executar a coleta
codigo = caminho_coletor.read_text(encoding="utf-8")
arvore = ast.parse(codigo)

# Localizar somente a função consultar_nvd
funcao = next(
    no
    for no in arvore.body
    if isinstance(no, ast.FunctionDef)
    and no.name == "consultar_nvd"
)

# Criar um módulo contendo apenas essa função
modulo_teste = ast.Module(
    body=[funcao],
    type_ignores=[]
)

ast.fix_missing_locations(modulo_teste)

# Configurações necessárias para executar a função
import requests
import time

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"User-Agent": "CyberThreatIntelligence-Learning/1.0"}
MAX_TENTATIVAS = 3
INTERVALO = 6

ambiente = {
    "requests": requests,
    "time": time,
    "URL": URL,
    "HEADERS": HEADERS,
    "MAX_TENTATIVAS": MAX_TENTATIVAS,
    "INTERVALO": INTERVALO
}

exec(
    compile(modulo_teste, str(caminho_coletor), "exec"),
    ambiente
)

consultar_nvd = ambiente["consultar_nvd"]

# Simular duas falhas e uma resposta bem-sucedida
erro_503 = Mock()
erro_503.status_code = 503
erro_503.headers = {}

sucesso_200 = Mock()
sucesso_200.status_code = 200
sucesso_200.headers = {}
sucesso_200.raise_for_status.return_value = None

respostas = [erro_503, erro_503, sucesso_200]

with patch.object(
    requests,
    "get",
    side_effect=respostas
) as requisicao_simulada:

    with patch.object(
        time,
        "sleep"
    ) as espera_simulada:

        resposta = consultar_nvd(
            {"resultsPerPage": 5, "startIndex": 0}
        )

# Validar o comportamento
assert resposta.status_code == 200
assert requisicao_simulada.call_count == 3

tempos_espera = [
    chamada.args[0]
    for chamada in espera_simulada.call_args_list
]

assert tempos_espera == [6, 12], (
    f"Intervalos inesperados: {tempos_espera}"
)

print("\nRESULTADO DO TESTE")
print("Chamadas HTTP simuladas:", requisicao_simulada.call_count)
print("Intervalos de espera:", tempos_espera)
print("Resposta final:", resposta.status_code)
print("Teste de backoff: OK")
