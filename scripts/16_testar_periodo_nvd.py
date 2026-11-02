
import requests


# ==========================================
# CONFIGURAÇÕES DA API
# ==========================================

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

PARAMETROS = {
    "pubStartDate": "2026-10-01T00:00:00.000Z",
    "pubEndDate": "2026-10-07T23:59:59.999Z",
    "resultsPerPage": 5,
    "startIndex": 0
}

HEADERS = {
    "User-Agent": "CyberThreatIntelligence-Learning/1.0"
}


# ==========================================
# CONSULTAR A NVD
# ==========================================

print("Consultando vulnerabilidades publicadas...")
print("Período: 01/10/2026 a 07/10/2026")

resposta = requests.get(
    URL,
    params=PARAMETROS,
    headers=HEADERS,
    timeout=30
)

print("Status HTTP:", resposta.status_code)

resposta.raise_for_status()

dados = resposta.json()


# ==========================================
# ANALISAR O RESULTADO
# ==========================================

total = dados["totalResults"]
registros = dados["vulnerabilities"]

print("\nRESULTADO DA CONSULTA")
print("Total de CVEs no período:", total)
print("Registros nesta página:", len(registros))

print("\nEXEMPLOS DE CVEs")

for item in registros:
    cve = item["cve"]

    print(
        cve["id"],
        "| Publicação:",
        cve.get("published", "Não informada")
    )

print("\nTeste de consulta temporal: OK")
