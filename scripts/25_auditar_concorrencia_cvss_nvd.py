
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

concorrencias = Counter()
cves_com_concorrencia = set()
exemplos = []

total_cves = 0


# ==========================================
# ANALISAR AVALIAÇÕES
# ==========================================

for arquivo_dados in arquivos:

    with arquivo_dados.open(
        "r",
        encoding="utf-8"
    ) as arquivo:
        dados = json.load(arquivo)

    for item in dados["vulnerabilities"]:

        cve = item["cve"]
        identificador = cve["id"]
        metrics = cve.get("metrics") or {}

        total_cves += 1

        for versao in VERSOES:

            avaliacoes = metrics.get(versao, [])

            validas = [
                avaliacao
                for avaliacao in avaliacoes
                if isinstance(
                    (avaliacao.get("cvssData") or {}).get(
                        "baseScore"
                    ),
                    (int, float)
                )
            ]

            if len(validas) > 1:

                concorrencias[versao] += 1
                cves_com_concorrencia.add(identificador)

                if len(exemplos) < 5:

                    exemplos.append({
                        "cve": identificador,
                        "versao": versao,
                        "avaliacoes": [
                            {
                                "source": avaliacao.get("source"),
                                "type": avaliacao.get("type"),
                                "score": (
                                    avaliacao.get("cvssData") or {}
                                ).get("baseScore")
                            }
                            for avaliacao in validas
                        ]
                    })


# ==========================================
# RESULTADO
# ==========================================

print("Coleta:", pasta_coleta.name)

print("\nAUDITORIA DE CONCORRÊNCIA CVSS")

print("Total de CVEs:", total_cves)

print(
    "CVEs com avaliações concorrentes:",
    len(cves_com_concorrencia)
)

print("\nCONCORRÊNCIAS POR VERSÃO")

for versao in VERSOES:
    print(
        f"{versao}: {concorrencias[versao]} CVEs"
    )

print("\nEXEMPLOS")

for exemplo in exemplos:
    print(
        json.dumps(
            exemplo,
            indent=2,
            ensure_ascii=False
        )
    )

print("\nAuditoria de concorrência: OK")
