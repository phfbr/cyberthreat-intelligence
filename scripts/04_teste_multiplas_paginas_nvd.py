
import time
import requests

# Endpoint oficial da NVD
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Configurações do teste
registros_por_pagina = 5
quantidade_paginas = 2

# Lista para armazenar os identificadores encontrados
cves_coletadas = []

# Percorrer duas páginas
for pagina in range(quantidade_paginas):

    # Calcular o índice inicial de cada página
    indice_inicial = pagina * registros_por_pagina

    parametros = {
        "resultsPerPage": registros_por_pagina,
        "startIndex": indice_inicial
    }

    print(f"\nConsultando página {pagina + 1}...")

    resposta = requests.get(
        url,
        params=parametros,
        headers={"User-Agent": "CyberThreatIntelligence-Learning/1.0"},
        timeout=30
    )

    resposta.raise_for_status()
    dados = resposta.json()

    # Extrair os identificadores CVE
    for item in dados["vulnerabilities"]:
        cve_id = item["cve"]["id"]
        cves_coletadas.append(cve_id)
        print("-", cve_id)

    # Aguardar antes da próxima requisição
    if pagina < quantidade_paginas - 1:
        time.sleep(6)

# Exibir o resumo
print("\nRESUMO DA COLETA")
print("Total coletado:", len(cves_coletadas))
print("CVEs únicas:", len(set(cves_coletadas)))
print("Duplicidades:", len(cves_coletadas) - len(set(cves_coletadas)))
