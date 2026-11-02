
import json
from pathlib import Path

from nvd_coletas import selecionar_coleta_concluida


# ==========================================
# LOCALIZAR COLETA TEMPORAL
# ==========================================

pasta_nvd = Path("data/bronze/nvd")

pasta_coleta = selecionar_coleta_concluida(
    pasta_nvd
)

with (
    pasta_coleta / "status_coleta.json"
).open("r", encoding="utf-8") as arquivo:
    controle = json.load(arquivo)

if controle.get("tipo_coleta") != "publicacao":
    raise ValueError(
        "A coleta selecionada não é temporal."
    )

print("Coleta:", pasta_coleta.name)


# ==========================================
# VALIDAR ARQUIVOS E METADADOS
# ==========================================

arquivos = sorted(
    pasta_coleta.glob("pagina_[0-9][0-9][0-9].json")
)

total_registros = 0
proximo_indice = 0

for arquivo_dados in arquivos:

    numero_pagina = int(
        arquivo_dados.stem.split("_")[1]
    )

    arquivo_metadados = (
        pasta_coleta
        / f"pagina_{numero_pagina:03d}_metadata.json"
    )

    if not arquivo_metadados.is_file():
        raise FileNotFoundError(
            f"Metadados ausentes: {arquivo_metadados.name}"
        )

    with arquivo_dados.open("rb") as arquivo:
        conteudo_original = arquivo.read()

    dados = json.loads(conteudo_original)

    with arquivo_metadados.open(
        "r",
        encoding="utf-8"
    ) as arquivo:
        metadados = json.load(arquivo)

    quantidade = len(dados["vulnerabilities"])
    indice = dados["startIndex"]

    assert numero_pagina == len(
        arquivos[:numero_pagina]
    ), "Numeração inesperada de página."

    assert indice == proximo_indice, (
        "Sequência de paginação inconsistente."
    )

    assert metadados["indice_inicial"] == indice
    assert metadados["quantidade_registros"] == quantidade
    assert metadados["tamanho_bytes"] == len(conteudo_original)
    assert metadados["arquivo_dados"] == arquivo_dados.name
    assert metadados["status_http"] == 200

    assert (
        metadados["periodo_inicio"]
        == controle["periodo_inicio"]
    )

    assert (
        metadados["periodo_fim"]
        == controle["periodo_fim"]
    )

    total_registros += quantidade
    proximo_indice += quantidade

    print(
        f"{arquivo_dados.name}: "
        f"{quantidade} registros | "
        f"{len(conteudo_original)} bytes | OK"
    )


# ==========================================
# VALIDAR CONTROLE DA COLETA
# ==========================================

assert controle["status"] == "concluida"

assert controle["paginas_coletadas"] == len(arquivos)

assert controle["registros_coletados"] == total_registros

print("\nRESULTADO DA INTEGRIDADE")
print("Páginas validadas:", len(arquivos))
print("Registros validados:", total_registros)
print("Último índice alcançado:", proximo_indice)
print("Status da coleta:", controle["status"])
print("Integridade Bronze: OK")
