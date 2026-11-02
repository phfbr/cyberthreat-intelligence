
import json
from pathlib import Path

from nvd_coletas import selecionar_coleta_concluida
from cvss_selecao import selecionar_cvss_referencia


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
        "Nenhuma página JSON encontrada."
    )


# ==========================================
# CONTADORES
# ==========================================

total_rejeitadas = 0
rejeitadas_com_cvss = 0
rejeitadas_sem_cvss = 0

rejeitadas_com_referencias = 0
rejeitadas_sem_referencias = 0


# ==========================================
# AUDITORIA
# ==========================================

for caminho in arquivos:

    with caminho.open(
        "r",
        encoding="utf-8"
    ) as arquivo:
        dados = json.load(arquivo)

    for item in dados["vulnerabilities"]:

        cve = item["cve"]

        if cve.get("vulnStatus") != "Rejected":
            continue

        total_rejeitadas += 1

        resultado_cvss = selecionar_cvss_referencia(
            cve.get("metrics")
        )

        if resultado_cvss is None:
            rejeitadas_sem_cvss += 1
        else:
            rejeitadas_com_cvss += 1

        referencias = cve.get("references") or []

        if referencias:
            rejeitadas_com_referencias += 1
        else:
            rejeitadas_sem_referencias += 1

        descricoes = [
            descricao.get("value", "")
            for descricao in cve.get("descriptions", [])
            if descricao.get("lang") == "en"
        ]

        texto = descricoes[0] if descricoes else ""

        print("\n" + "-" * 50)
        print("CVE:", cve["id"])
        print("Status:", cve["vulnStatus"])

        print(
            "CVSS:",
            resultado_cvss["pontuacao"]
            if resultado_cvss else "SEM_CVSS"
        )

        print("Referências:", len(referencias))
        print("Descrição:", texto[:250])


# ==========================================
# RESUMO
# ==========================================

print("\n" + "=" * 50)
print("RESUMO — CVEs REJEITADAS")

print("Coleta:", pasta_coleta.name)
print("Total rejeitadas:", total_rejeitadas)

print("Com CVSS:", rejeitadas_com_cvss)
print("Sem CVSS:", rejeitadas_sem_cvss)

print(
    "Com referências:",
    rejeitadas_com_referencias
)

print(
    "Sem referências:",
    rejeitadas_sem_referencias
)


# ==========================================
# VALIDAÇÕES
# ==========================================

assert (
    total_rejeitadas
    == rejeitadas_com_cvss + rejeitadas_sem_cvss
)

assert (
    total_rejeitadas
    == rejeitadas_com_referencias
    + rejeitadas_sem_referencias
)

assert total_rejeitadas == 17

print("\nAuditoria de rejeitadas: OK")
