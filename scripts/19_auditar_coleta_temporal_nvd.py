
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from nvd_coletas import selecionar_coleta_concluida


# ==========================================
# LOCALIZAR A COLETA
# ==========================================

pasta_nvd = Path("data/bronze/nvd")

pasta_coleta = selecionar_coleta_concluida(
    pasta_nvd
)

arquivo_status = pasta_coleta / "status_coleta.json"

with arquivo_status.open(
    "r",
    encoding="utf-8"
) as arquivo:
    controle = json.load(arquivo)

if controle.get("tipo_coleta") != "publicacao":
    raise ValueError(
        "A coleta selecionada não é temporal."
    )

inicio = datetime.fromisoformat(
    controle["periodo_inicio"].replace("Z", "+00:00")
)

fim = datetime.fromisoformat(
    controle["periodo_fim"].replace("Z", "+00:00")
)

print("Coleta selecionada:", pasta_coleta.name)


# ==========================================
# AUDITAR AS PÁGINAS
# ==========================================

arquivos = sorted(
    pasta_coleta.glob("pagina_[0-9][0-9][0-9].json")
)

ids_cve = []
fora_periodo = []
registros_sem_id = []
registros_sem_data = []
indices = []
total_arquivos = 0

for arquivo_dados in arquivos:

    with arquivo_dados.open(
        "r",
        encoding="utf-8"
    ) as arquivo:
        dados = json.load(arquivo)

    registros = dados["vulnerabilities"]
    indice = dados["startIndex"]

    indices.append(indice)
    total_arquivos += len(registros)

    print(
        f"{arquivo_dados.name}: "
        f"{len(registros)} registros"
    )

    for item in registros:

        cve = item["cve"]

        identificador = cve.get("id")
        publicacao = cve.get("published")

        if not identificador:
            registros_sem_id.append(cve)
            continue

        ids_cve.append(identificador)

        if not publicacao:
            registros_sem_data.append(identificador)
            continue

        data_publicacao = datetime.fromisoformat(
            publicacao.replace("Z", "+00:00")
        )

        # A NVD pode retornar datas sem fuso explícito.
        # Nesse caso, interpretamos como UTC.
        if data_publicacao.tzinfo is None:
            from datetime import timezone
            data_publicacao = data_publicacao.replace(
                tzinfo=timezone.utc
            )

        if not inicio <= data_publicacao <= fim:
            fora_periodo.append(identificador)


# ==========================================
# VERIFICAR DUPLICIDADES
# ==========================================

contagem = Counter(ids_cve)

duplicadas = [
    identificador
    for identificador, quantidade in contagem.items()
    if quantidade > 1
]

total_esperado = controle["registros_coletados"]


# ==========================================
# RELATÓRIO
# ==========================================

print("\nRESULTADO DA AUDITORIA")

print("Arquivos de páginas:", len(arquivos))
print("Registros encontrados:", total_arquivos)
print("Registros esperados:", total_esperado)
print("CVEs únicas:", len(contagem))
print("CVEs duplicadas:", len(duplicadas))
print("Registros sem ID:", len(registros_sem_id))
print("Registros sem data:", len(registros_sem_data))
print("Publicações fora do período:", len(fora_periodo))
print("Índices encontrados:", indices)


# ==========================================
# VALIDAÇÃO FINAL
# ==========================================

assert total_arquivos == total_esperado
assert len(duplicadas) == 0
assert len(registros_sem_id) == 0
assert len(registros_sem_data) == 0
assert len(fora_periodo) == 0

print("\nAuditoria temporal: OK")
