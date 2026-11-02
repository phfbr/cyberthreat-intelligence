
import json
from pathlib import Path
from nvd_coletas import selecionar_coleta_concluida

# Pasta da coleta que acabamos de executar
# Diretório que contém todas as coletas NVD


# ==========================================
# SELECIONAR A ÚLTIMA COLETA CONCLUÍDA
# ==========================================

pasta_nvd = Path("data/bronze/nvd")

pasta_coleta = selecionar_coleta_concluida(
    pasta_nvd
)

print("Coleta selecionada:", pasta_coleta.name)


# Localizar os arquivos de dados
arquivos = sorted(pasta_coleta.glob("pagina_[0-9][0-9][0-9].json"))

# Lista para reunir os identificadores CVE
cves = []

assert len(arquivos) == 2, "Quantidade de páginas inesperada"

for arquivo in arquivos:

    # Ler o JSON original
    with arquivo.open("r", encoding="utf-8") as f:
        dados = json.load(f)

    # Localizar os metadados correspondentes
    arquivo_metadados = arquivo.with_name(
        arquivo.stem + "_metadata.json"
    )

    with arquivo_metadados.open("r", encoding="utf-8") as f:
        metadados = json.load(f)

    # Validar os dados armazenados
    registros = dados["vulnerabilities"]

    assert len(registros) == 5, (
        f"Quantidade inesperada em {arquivo.name}"
    )

    assert len(registros) == metadados["quantidade_registros"], (
        f"Metadados inconsistentes em {arquivo.name}"
    )

    assert arquivo.stat().st_size == metadados["tamanho_bytes"], (
        f"Tamanho inconsistente em {arquivo.name}"
    )

    assert metadados["arquivo_dados"] == arquivo.name, (
        f"Nome inconsistente em {arquivo.name}"
    )

    assert metadados["status_http"] == 200, (
        f"Status HTTP inválido em {arquivo.name}"
    )

    assert dados["startIndex"] == metadados["indice_inicial"], (
        f"Índice inicial inconsistente em {arquivo.name}"
    )

    # Reunir os identificadores CVE
    for item in registros:
        cves.append(item["cve"]["id"])

    print(f"{arquivo.name}: OK — {len(registros)} registros")

# Verificar duplicidades entre páginas
total = len(cves)
unicos = len(set(cves))
duplicados = total - unicos

print("\nRESULTADO DA VALIDAÇÃO")
print("Páginas validadas:", len(arquivos))
print("Total de registros:", total)
print("CVEs únicas:", unicos)
print("Duplicidades:", duplicados)

assert duplicados == 0, "Foram encontradas CVEs duplicadas"

print("Validação da coleta Bronze: OK")
