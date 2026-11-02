
import requests

# Endpoint oficial da API NVD
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Configuração da consulta
parametros = {
    "resultsPerPage": 5,
    "startIndex": 0
}

# Consultar a API
resposta = requests.get(
    url,
    params=parametros,
    headers={"User-Agent": "CyberThreatIntelligence-Learning/1.0"},
    timeout=30
)

# Verificar se a requisição funcionou
print("Status HTTP:", resposta.status_code)
resposta.raise_for_status()

# Converter o JSON para Python
dados = resposta.json()

# Consultar as informações da paginação
print("Total de registros:", dados["totalResults"])
print("Registros nesta página:", len(dados["vulnerabilities"]))
print("Índice inicial:", dados["startIndex"])
print("Resultados por página:", dados["resultsPerPage"])

# Exibir os identificadores das CVEs recebidas
print("\nCVEs encontradas:")

for item in dados["vulnerabilities"]:
    print("-", item["cve"]["id"])
