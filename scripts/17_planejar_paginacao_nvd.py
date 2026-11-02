
import math
import requests


# ==========================================
# CONFIGURAÇÕES
# ==========================================

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

REGISTROS_POR_PAGINA = 2000

PARAMETROS = {
    "pubStartDate": "2026-10-01T00:00:00.000Z",
    "pubEndDate": "2026-10-07T23:59:59.999Z",
    "resultsPerPage": 1,
    "startIndex": 0
}


# ==========================================
# CONSULTAR O TOTAL DE REGISTROS
# ==========================================

resposta = requests.get(
    URL,
    params=PARAMETROS,
    headers={
        "User-Agent": "CyberThreatIntelligence-Learning/1.0"
    },
    timeout=30
)

resposta.raise_for_status()

dados = resposta.json()

total_registros = dados["totalResults"]


# ==========================================
# CALCULAR A PAGINAÇÃO
# ==========================================

total_paginas = math.ceil(
    total_registros / REGISTROS_POR_PAGINA
)

print("\nPLANEJAMENTO DA COLETA NVD")
print("Total de CVEs:", total_registros)
print("Registros por página:", REGISTROS_POR_PAGINA)
print("Páginas necessárias:", total_paginas)

print("\nÍNDICES DE PAGINAÇÃO")

for pagina in range(total_paginas):

    indice_inicial = pagina * REGISTROS_POR_PAGINA

    quantidade_prevista = min(
        REGISTROS_POR_PAGINA,
        total_registros - indice_inicial
    )

    print(
        f"Página {pagina + 1}: "
        f"startIndex={indice_inicial} | "
        f"registros previstos={quantidade_prevista}"
    )

print("\nPlanejamento concluído.")
