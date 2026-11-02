
import json
from collections import Counter
from pathlib import Path

from nvd_coletas import selecionar_coleta_concluida
from cvss_selecao import selecionar_cvss_referencia


def severidade_esperada(pontuacao, versao):
    """
    Calcula a severidade pela faixa de pontuação
    para CVSS 3.0, 3.1 e 4.0.
    """

    if versao not in ("3.0", "3.1", "4.0"):
        return None

    if pontuacao == 0:
        return "NONE"
    if pontuacao < 4.0:
        return "LOW"
    if pontuacao < 7.0:
        return "MEDIUM"
    if pontuacao < 9.0:
        return "HIGH"

    return "CRITICAL"


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

resultados = Counter()
inconsistencias = []


# ==========================================
# VALIDAR CVES
# ==========================================

for caminho in arquivos:

    with caminho.open(
        "r",
        encoding="utf-8"
    ) as arquivo:
        dados = json.load(arquivo)

    for item in dados["vulnerabilities"]:

        cve = item["cve"]

        resultado = selecionar_cvss_referencia(
            cve.get("metrics")
        )

        if resultado is None:
            resultados["sem_cvss"] += 1
            continue

        esperada = severidade_esperada(
            resultado["pontuacao"],
            resultado["versao"]
        )

        informada = resultado["severidade"]

        if esperada is None:
            resultados["nao_verificavel"] += 1

        elif informada is None:
            resultados["sem_severidade"] += 1

        elif str(informada).upper() == esperada:
            resultados["coerente"] += 1

        else:
            resultados["inconsistente"] += 1

            inconsistencias.append({
                "cve": cve["id"],
                "versao": resultado["versao"],
                "pontuacao": resultado["pontuacao"],
                "informada": informada,
                "esperada": esperada
            })


# ==========================================
# RELATÓRIO
# ==========================================

print("Coleta:", pasta_coleta.name)

print("\nCOERÊNCIA CVSS")

for categoria in [
    "coerente",
    "inconsistente",
    "sem_severidade",
    "nao_verificavel",
    "sem_cvss"
]:
    print(
        f"{categoria}: {resultados[categoria]}"
    )

print("\nEXEMPLOS DE INCONSISTÊNCIAS")

for exemplo in inconsistencias[:10]:
    print(exemplo)


# ==========================================
# VALIDAÇÃO DE CONTAGEM
# ==========================================

total = sum(resultados.values())

print("\nTotal auditado:", total)

assert total == 2743, (
    f"Quantidade inesperada: {total}"
)

print("\nAuditoria de coerência: OK")
