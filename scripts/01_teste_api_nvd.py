
import requests

# Endereço oficial da API NVD
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Vulnerabilidade que queremos consultar
parametros = {
    "cveId": "CVE-2021-44228"
}

# Enviar a requisição para a API
resposta = requests.get(
    url,
    params=parametros,
    timeout=30
)

# Verificar o resultado da requisição
print("Status HTTP:", resposta.status_code)

# Interromper se a API retornar um erro
resposta.raise_for_status()

# Converter a resposta JSON para Python
dados = resposta.json()

# Acessar o primeiro registro de vulnerabilidade
vulnerabilidade = dados["vulnerabilities"][0]["cve"]

# Mostrar as informações principais
print("CVE:", vulnerabilidade["id"])
print("Publicação:", vulnerabilidade["published"])
print("Última atualização:", vulnerabilidade["lastModified"])

# Inspecionar os campos disponíveis na CVE
print("\nCampos disponíveis na vulnerabilidade:")

for campo in vulnerabilidade.keys():
    print("-", campo)

# Inspecionar as versões CVSS disponíveis
print("\nVersões CVSS disponíveis:")

for versao in vulnerabilidade["metrics"].keys():
    print("-", versao)

# Acessar a primeira métrica CVSS 3.1
metricas = vulnerabilidade["metrics"]["cvssMetricV31"][0]

# Extrair as informações de severidade
cvss = metricas["cvssData"]

print("\nInformações CVSS 3.1:")
print("Pontuação:", cvss["baseScore"])
print("Severidade:", cvss["baseSeverity"])
print("Vetor:", cvss["vectorString"])
print("Origem da avaliação:", metricas["source"])

import json
from pathlib import Path

# Definir a pasta de armazenamento Bronze
pasta_bronze = Path("data/bronze/nvd")

# Criar a pasta caso ainda não exista
pasta_bronze.mkdir(parents=True, exist_ok=True)

# Definir o nome do arquivo JSON
arquivo = pasta_bronze / "CVE-2021-44228.json"

# Salvar a resposta JSON original da API
with arquivo.open("wb") as f:
    f.write(resposta.content)

print("\nArquivo salvo em:", arquivo)

from datetime import datetime, timezone

# Registrar o momento da coleta em UTC
data_coleta = datetime.now(timezone.utc).isoformat()

# Montar os metadados da coleta
metadados = {
    "fonte": "NIST NVD",
    "api": url,
    "cve_consultada": parametros["cveId"],
    "data_coleta_utc": data_coleta,
    "status_http": resposta.status_code,
    "quantidade_registros": len(dados["vulnerabilities"]),
    "arquivo_dados": arquivo.name,
    "tamanho_bytes": arquivo.stat().st_size
}

# Definir o arquivo de metadados
arquivo_metadados = pasta_bronze / "CVE-2021-44228_metadata.json"

# Salvar os metadados em JSON
with arquivo_metadados.open("w", encoding="utf-8") as f:
    json.dump(metadados, f, indent=4, ensure_ascii=False)

print("Metadados salvos em:", arquivo_metadados)
print("Data da coleta (UTC):", data_coleta)
