
import json
from collections import Counter
from pathlib import Path

from nvd_coletas import selecionar_coleta_concluida
from cvss_selecao import (
    selecionar_cvss_referencia,
    VERSOES_CVSS
)


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
cves_com_primary = 0
primary_selecionada = 0
primary_nao_selecionada = 0

combinacoes = Counter()
exemplos = []


# ==========================================
# ANALISAR CADA CVE
# ==========================================

for caminho in arquivos:

    with caminho.open(
        "r",
        encoding="utf-8"
    ) as arquivo:
        dados = json.load(arquivo)

    for item in dados["vulnerabilities"]:

        cve = item["cve"]
        metrics = cve.get("metrics") or {}

        total_cves += 1

        selecionada = selecionar_cvss_referencia(
            metrics
        )

        avaliacoes_primary = []

        for metrica in VERSOES_CVSS:

            for avaliacao in metrics.get(metrica, []):

                if avaliacao.get("type") != "Primary":
                    continue

                # Aplicar os mesmos critérios de validade
                # da função oficial de seleção.
                primaria_valida = selecionar_cvss_referencia({
                    metrica: [avaliacao]
                })

                if primaria_valida is not None:
                    avaliacoes_primary.append(
                        primaria_valida
                    )

        if not avaliacoes_primary:
            continue

        cves_com_primary += 1

        if (
            selecionada is not None
            and selecionada["tipo"] == "Primary"
        ):
            primary_selecionada += 1
            continue

        primary_nao_selecionada += 1

        for primaria in avaliacoes_primary:

            chave = (
                primaria["versao"],
                selecionada["versao"]
                if selecionada else "SEM_CVSS"
            )

            combinacoes[chave] += 1

        if len(exemplos) < 10:
            exemplos.append({
                "cve": cve["id"],
                "primary_disponivel": [
                    {
                        "versao": p["versao"],
                        "pontuacao": p["pontuacao"]
                    }
                    for p in avaliacoes_primary
                ],
                "selecionada": {
                    "versao": selecionada["versao"],
                    "tipo": selecionada["tipo"],
                    "pontuacao": selecionada["pontuacao"],
                    "fonte": selecionada["fonte"]
                } if selecionada else None
            })


# ==========================================
# RELATÓRIO
# ==========================================

print("Coleta:", pasta_coleta.name)

print("\nIMPACTO DA PRIORIDADE DE VERSÃO")

print("Total de CVEs:", total_cves)

print(
    "CVEs com Primary válida:",
    cves_com_primary
)

print(
    "Primary selecionada:",
    primary_selecionada
)

print(
    "Primary não selecionada:",
    primary_nao_selecionada
)

print("\nCOMBINAÇÕES AFETADAS")

for combinacao, quantidade in sorted(
    combinacoes.items()
):
    print(
        f"Primary {combinacao[0]} -> "
        f"Selecionada {combinacao[1]}: "
        f"{quantidade}"
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


# ==========================================
# VALIDAÇÕES
# ==========================================

assert total_cves == 2743

assert (
    cves_com_primary
    == primary_selecionada + primary_nao_selecionada
)

print("\nAuditoria de prioridade: OK")
