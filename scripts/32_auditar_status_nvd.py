
import json
from collections import Counter
from pathlib import Path

from nvd_coletas import selecionar_coleta_concluida


# ==========================================
# LOCALIZAR COLETA
# ==========================================

pasta_coleta = selecionar_coleta_concluida(
    Path("data/bronze/nvd")
)

arquivos = sorted(
    pasta_coleta.glob("pagina_[0-9][0-9][0-9].json")
)

if not arquivos:
    raise FileNotFoundError(
        "Nenhuma página JSON encontrada na coleta."
    )


# ==========================================
# CONTADORES
# ==========================================

total_cves = 0
status_contagem = Counter()

status_ausente = 0
status_vazio = 0

exemplos_por_status = {}


# ==========================================
# AUDITAR STATUS
# ==========================================

for caminho in arquivos:

    with caminho.open(
        "r",
        encoding="utf-8"
    ) as arquivo:
        dados = json.load(arquivo)

    for item in dados["vulnerabilities"]:

        cve = item["cve"]
        total_cves += 1

        status = cve.get("vulnStatus")

        if status is None:
            status_ausente += 1
            status_tratado = "AUSENTE"

        elif not isinstance(status, str) or not status.strip():
            status_vazio += 1
            status_tratado = "VAZIO"

        else:
            status_tratado = status.strip()

        status_contagem[status_tratado] += 1

        if status_tratado not in exemplos_por_status:
            exemplos_por_status[status_tratado] = cve["id"]


# ==========================================
# RELATÓRIO
# ==========================================

print("Coleta:", pasta_coleta.name)

print("\nAUDITORIA DE STATUS NVD")

print("Total de CVEs:", total_cves)
print("Status ausente:", status_ausente)
print("Status vazio:", status_vazio)

print("\nDISTRIBUIÇÃO DOS STATUS")

for status, quantidade in status_contagem.most_common():

    percentual = (
        quantidade / total_cves * 100
        if total_cves else 0
    )

    print(
        f"{status}: {quantidade} CVEs "
        f"({percentual:.2f}%)"
    )


print("\nEXEMPLO POR STATUS")

for status, identificador in sorted(
    exemplos_por_status.items()
):
    print(f"{status}: {identificador}")


# ==========================================
# VALIDAÇÕES
# ==========================================

assert sum(status_contagem.values()) == total_cves

assert (
    status_ausente + status_vazio
    <= total_cves
)

print("\nAuditoria de status: OK")
