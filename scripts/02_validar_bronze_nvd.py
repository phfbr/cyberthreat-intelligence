
import json
from pathlib import Path

# Localizar o arquivo armazenado na Bronze
arquivo = Path("data/bronze/nvd/CVE-2021-44228.json")

# Verificar se o arquivo existe
if not arquivo.is_file():
    raise FileNotFoundError(f"Arquivo não encontrado: {arquivo}")

# Abrir e interpretar o JSON
with arquivo.open("r", encoding="utf-8") as f:
    dados = json.load(f)

# Verificar a quantidade de registros
total = len(dados["vulnerabilities"])

# Recuperar o identificador da CVE
cve = dados["vulnerabilities"][0]["cve"]["id"]

# Validar o conteúdo esperado
assert total == 1, "Quantidade inesperada de registros"
assert cve == "CVE-2021-44228", "Identificador CVE incorreto"

print("Arquivo:", arquivo.name)
print("Tamanho (bytes):", arquivo.stat().st_size)
print("Total de registros:", total)
print("CVE:", cve)
print("Validação Bronze: OK")

# Localizar o arquivo de metadados
arquivo_metadados = Path(
    "data/bronze/nvd/CVE-2021-44228_metadata.json"
)

# Ler os metadados
with arquivo_metadados.open("r", encoding="utf-8") as f:
    metadados = json.load(f)

# Comparar os metadados com o arquivo original
assert metadados["status_http"] == 200, "Status HTTP inválido"

assert metadados["quantidade_registros"] == total, (
    "Quantidade de registros inconsistente"
)

assert metadados["cve_consultada"] == cve, (
    "Identificador CVE inconsistente"
)

assert metadados["tamanho_bytes"] == arquivo.stat().st_size, (
    "Tamanho do arquivo inconsistente"
)

assert metadados["arquivo_dados"] == arquivo.name, (
    "Nome do arquivo inconsistente"
)

print("\nValidação dos metadados: OK")
print("Fonte:", metadados["fonte"])
print("Data da coleta:", metadados["data_coleta_utc"])
print("Registros validados:", metadados["quantidade_registros"])
