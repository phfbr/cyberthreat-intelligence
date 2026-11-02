
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


# ==========================================
# CONTADORES
# ==========================================

versoes_cvss = Counter()
severidades = Counter()

total_cves = 0
sem_pontuacao = 0
com_pontuacao = 0

exemplo_metricas = None


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

        cve = item["cve"]
        metrics = cve.get("metrics") or {}

        total_cves += 1
        possui_pontuacao = False

        if metrics and exemplo_metricas is None:
            exemplo_metricas = metrics

        for nome_metrica, avaliacoes in metrics.items():

            versoes_cvss[nome_metrica] += 1

            if not isinstance(avaliacoes, list):
                continue

            for avaliacao in avaliacoes:

                dados_cvss = avaliacao.get("cvssData") or {}

                pontuacao = dados_cvss.get("baseScore")

                if isinstance(pontuacao, (int, float)):
                    possui_pontuacao = True

                    severidade = (
                        dados_cvss.get("baseSeverity")
                        or avaliacao.get("baseSeverity")
                        or "NAO_INFORMADA"
                    )

                    severidades[severidade] += 1

        if possui_pontuacao:
            com_pontuacao += 1
        else:
            sem_pontuacao += 1


# ==========================================
# RELATÓRIO
# ==========================================

print("Coleta:", pasta_coleta.name)

print("\nAUDITORIA CVSS")
print("Total de CVEs:", total_cves)
print("CVEs com pontuação:", com_pontuacao)
print("CVEs sem pontuação:", sem_pontuacao)

print("\nTIPOS DE MÉTRICAS ENCONTRADOS")

for nome, quantidade in sorted(
    versoes_cvss.items()
):
    print(f"{nome}: {quantidade} CVEs")

print("\nSEVERIDADES DAS AVALIAÇÕES")

for severidade, quantidade in sorted(
    severidades.items()
):
    print(f"{severidade}: {quantidade}")

print("\nEXEMPLO DE ESTRUTURA DAS MÉTRICAS")

if exemplo_metricas:
    for nome, avaliacoes in exemplo_metricas.items():

        print("Métrica:", nome)

        if isinstance(avaliacoes, list) and avaliacoes:
            print(
                json.dumps(
                    avaliacoes[0],
                    indent=2,
                    ensure_ascii=False
                )[:1800]
            )

        break

print("\nAuditoria CVSS concluída.")
