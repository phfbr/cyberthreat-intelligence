
import json
from collections import Counter
from pathlib import Path

from nvd_coletas import selecionar_coleta_concluida


# ==========================================
# LOCALIZAR A COLETA
# ==========================================

pasta_coleta = selecionar_coleta_concluida(
    Path("data/bronze/nvd")
)

arquivos = sorted(
    pasta_coleta.glob("pagina_[0-9][0-9][0-9].json")
)


# ==========================================
# CONFIGURAÇÕES
# ==========================================

VERSOES_CVSS = [
    "cvssMetricV40",
    "cvssMetricV31",
    "cvssMetricV30",
    "cvssMetricV2"
]

tipos_por_versao = Counter()
fontes_por_versao = Counter()

avaliacoes_totais = 0
cves_com_multiplas_avaliacoes = 0


# ==========================================
# ANALISAR AS AVALIAÇÕES
# ==========================================

for arquivo_dados in arquivos:

    with arquivo_dados.open(
        "r",
        encoding="utf-8"
    ) as arquivo:
        dados = json.load(arquivo)

    for item in dados["vulnerabilities"]:

        cve = item["cve"]
        metrics = cve.get("metrics") or {}

        avaliacoes_da_cve = 0

        for versao in VERSOES_CVSS:

            avaliacoes = metrics.get(versao, [])

            for avaliacao in avaliacoes:

                dados_cvss = avaliacao.get("cvssData") or {}

                if not isinstance(
                    dados_cvss.get("baseScore"),
                    (int, float)
                ):
                    continue

                tipo = avaliacao.get(
                    "type", "NAO_INFORMADO"
                )

                fonte = avaliacao.get(
                    "source", "NAO_INFORMADA"
                )

                tipos_por_versao[
                    (versao, tipo)
                ] += 1

                fontes_por_versao[
                    (versao, fonte)
                ] += 1

                avaliacoes_totais += 1
                avaliacoes_da_cve += 1

        if avaliacoes_da_cve > 1:
            cves_com_multiplas_avaliacoes += 1


# ==========================================
# RELATÓRIO
# ==========================================

print("Coleta:", pasta_coleta.name)

print("\nAUDITORIA DE FONTES CVSS")

print("Total de avaliações:", avaliacoes_totais)

print(
    "CVEs com múltiplas avaliações:",
    cves_com_multiplas_avaliacoes
)

print("\nTIPOS POR VERSÃO")

for (versao, tipo), quantidade in sorted(
    tipos_por_versao.items()
):
    print(
        f"{versao} | {tipo}: {quantidade}"
    )

print("\nPRINCIPAIS FONTES POR VERSÃO")

for versao in VERSOES_CVSS:

    fontes = [
        (fonte, quantidade)
        for (versao_encontrada, fonte), quantidade
        in fontes_por_versao.items()
        if versao_encontrada == versao
    ]

    fontes.sort(
        key=lambda item: item[1],
        reverse=True
    )

    print(f"\n{versao}")

    for fonte, quantidade in fontes[:5]:
        print(f"  {fonte}: {quantidade}")

print("\nAuditoria de fontes CVSS concluída.")
