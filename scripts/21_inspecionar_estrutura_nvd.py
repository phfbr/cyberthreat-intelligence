
import json
from collections import Counter
from pathlib import Path

from nvd_coletas import selecionar_coleta_concluida


# ==========================================
# LOCALIZAR A COLETA
# ==========================================

pasta_nvd = Path("data/bronze/nvd")

pasta_coleta = selecionar_coleta_concluida(
    pasta_nvd
)

print("Coleta selecionada:", pasta_coleta.name)


# ==========================================
# INSPECIONAR CAMPOS
# ==========================================

arquivos = sorted(
    pasta_coleta.glob("pagina_[0-9][0-9][0-9].json")
)

frequencia_campos = Counter()
total_cves = 0
primeiro_exemplo = None

for arquivo_dados in arquivos:

    with arquivo_dados.open(
        "r",
        encoding="utf-8"
    ) as arquivo:
        dados = json.load(arquivo)

    for item in dados["vulnerabilities"]:

        cve = item["cve"]

        frequencia_campos.update(cve.keys())
        total_cves += 1

        if primeiro_exemplo is None:
            primeiro_exemplo = cve


# ==========================================
# EXIBIR RESULTADOS
# ==========================================

print("\nAUDITORIA ESTRUTURAL NVD")
print("Total de CVEs analisadas:", total_cves)

print("\nFREQUÊNCIA DOS CAMPOS")

for campo, quantidade in sorted(
    frequencia_campos.items()
):
    percentual = quantidade / total_cves * 100

    print(
        f"{campo}: "
        f"{quantidade} registros "
        f"({percentual:.2f}%)"
    )


# ==========================================
# INSPECIONAR UM EXEMPLO
# ==========================================

print("\nEXEMPLO DE ESTRUTURA")

if primeiro_exemplo:

    print("CVE:", primeiro_exemplo.get("id"))

    for campo, valor in primeiro_exemplo.items():

        print(
            f"{campo}: {type(valor).__name__}"
        )

print("\nAuditoria estrutural concluída.")
