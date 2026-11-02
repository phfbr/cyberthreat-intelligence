
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

VERSOES = [
    "cvssMetricV40",
    "cvssMetricV31",
    "cvssMetricV30",
    "cvssMetricV2"
]


# ==========================================
# CONTADORES
# ==========================================

combinacoes = Counter()
cves_com_primary = 0
cves_somente_secondary = 0
cves_sem_cvss = 0

total_cves = 0


# ==========================================
# ANALISAR REGISTROS
# ==========================================

for arquivo_dados in arquivos:

    with arquivo_dados.open(
        "r",
        encoding="utf-8"
    ) as arquivo:
        dados = json.load(arquivo)

    for item in dados["vulnerabilities"]:

        total_cves += 1

        metrics = item["cve"].get("metrics") or {}

        versoes_encontradas = []
        tipos_encontrados = set()

        for versao in VERSOES:

            avaliacoes = metrics.get(versao, [])

            avaliacoes_validas = [
                avaliacao
                for avaliacao in avaliacoes
                if isinstance(
                    (avaliacao.get("cvssData") or {}).get(
                        "baseScore"
                    ),
                    (int, float)
                )
            ]

            if avaliacoes_validas:

                versoes_encontradas.append(versao)

                for avaliacao in avaliacoes_validas:
                    tipos_encontrados.add(
                        avaliacao.get(
                            "type", "NAO_INFORMADO"
                        )
                    )

        if not versoes_encontradas:

            cves_sem_cvss += 1
            combinacoes["SEM_CVSS"] += 1

        else:

            combinacao = " + ".join(
                versoes_encontradas
            )

            combinacoes[combinacao] += 1

            if "Primary" in tipos_encontrados:
                cves_com_primary += 1
            else:
                cves_somente_secondary += 1


# ==========================================
# RELATÓRIO
# ==========================================

print("Coleta:", pasta_coleta.name)

print("\nCOMBINAÇÕES DE CVSS")

for combinacao, quantidade in (
    combinacoes.most_common()
):
    print(
        f"{combinacao}: {quantidade} CVEs"
    )

print("\nRESUMO")

print("Total de CVEs:", total_cves)
print("CVEs com Primary:", cves_com_primary)
print(
    "CVEs somente com Secondary:",
    cves_somente_secondary
)
print("CVEs sem CVSS:", cves_sem_cvss)

assert (
    cves_com_primary
    + cves_somente_secondary
    + cves_sem_cvss
    == total_cves
)

print("\nAuditoria de combinações: OK")
