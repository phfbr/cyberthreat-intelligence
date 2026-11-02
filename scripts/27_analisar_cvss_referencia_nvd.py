
import json
from collections import Counter
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


# ==========================================
# CONTADORES
# ==========================================

total_cves = 0
com_cvss = 0
sem_cvss = 0

versoes = Counter()
severidades = Counter()
fontes = Counter()
tipos = Counter()

exemplos = []


# ==========================================
# APLICAR A REGRA
# ==========================================

for arquivo_dados in arquivos:

    with arquivo_dados.open(
        "r",
        encoding="utf-8"
    ) as arquivo:
        dados = json.load(arquivo)

    for item in dados["vulnerabilities"]:

        cve = item["cve"]
        total_cves += 1

        resultado = selecionar_cvss_referencia(
            cve.get("metrics")
        )

        if resultado is None:
            sem_cvss += 1
            continue

        com_cvss += 1

        versoes[resultado["versao"]] += 1

        severidades[
            resultado["severidade"] or "NAO_INFORMADA"
        ] += 1

        fontes[
            resultado["fonte"] or "NAO_INFORMADA"
        ] += 1

        tipos[
            resultado["tipo"] or "NAO_INFORMADO"
        ] += 1

        if len(exemplos) < 5:
            exemplos.append({
                "cve": cve["id"],
                "versao": resultado["versao"],
                "pontuacao": resultado["pontuacao"],
                "severidade": resultado["severidade"],
                "fonte": resultado["fonte"],
                "tipo": resultado["tipo"]
            })


# ==========================================
# RELATÓRIO
# ==========================================

print("Coleta:", pasta_coleta.name)

print("\nCVSS DE REFERÊNCIA — V1")

print("Total de CVEs:", total_cves)
print("Com CVSS selecionado:", com_cvss)
print("Sem CVSS:", sem_cvss)

print("\nVERSÕES SELECIONADAS")

for versao, quantidade in sorted(versoes.items()):
    print(f"CVSS {versao}: {quantidade}")

print("\nSEVERIDADES SELECIONADAS")

for severidade, quantidade in sorted(
    severidades.items()
):
    print(f"{severidade}: {quantidade}")

print("\nTIPOS SELECIONADOS")

for tipo, quantidade in sorted(tipos.items()):
    print(f"{tipo}: {quantidade}")

print("\nTOP 10 FONTES SELECIONADAS")

for fonte, quantidade in fontes.most_common(10):
    print(f"{fonte}: {quantidade}")

print("\nEXEMPLOS")

for exemplo in exemplos:
    print(exemplo)


# ==========================================
# VALIDAÇÕES
# ==========================================

assert total_cves == com_cvss + sem_cvss
assert sum(versoes.values()) == com_cvss
assert sum(severidades.values()) == com_cvss
assert sum(fontes.values()) == com_cvss
assert sum(tipos.values()) == com_cvss

print("\nAnálise CVSS de referência: OK")
