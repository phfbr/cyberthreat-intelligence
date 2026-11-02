
import json
from collections import Counter
from datetime import datetime, timezone
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
        "Nenhuma página JSON encontrada na coleta."
    )


# ==========================================
# CONTADORES
# ==========================================

total_cves = 0
com_cvss = 0
sem_cvss = 0

versoes = Counter()
severidades = Counter()
tipos = Counter()
fontes = Counter()


# ==========================================
# ANALISAR CVES
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

        resultado = selecionar_cvss_referencia(
            cve.get("metrics")
        )

        if resultado is None:
            sem_cvss += 1
            continue

        com_cvss += 1

        versoes[
            resultado["versao"] or "NAO_INFORMADA"
        ] += 1

        severidades[
            resultado["severidade"] or "NAO_INFORMADA"
        ] += 1

        tipos[
            resultado["tipo"] or "NAO_INFORMADO"
        ] += 1

        fontes[
            resultado["fonte"] or "NAO_INFORMADA"
        ] += 1


# ==========================================
# VALIDAÇÕES
# ==========================================

assert total_cves == com_cvss + sem_cvss
assert sum(versoes.values()) == com_cvss
assert sum(severidades.values()) == com_cvss
assert sum(tipos.values()) == com_cvss
assert sum(fontes.values()) == com_cvss


# ==========================================
# CONSOLIDAR RELATÓRIO
# ==========================================

relatorio = {
    "projeto": (
        "CyberThreat Intelligence | "
        "Global Security Analytics"
    ),
    "coleta": pasta_coleta.name,
    "data_auditoria_utc": datetime.now(
        timezone.utc
    ).isoformat(),
    "regra_selecao": "CVSS_REFERENCIA_V1",
    "indicadores": {
        "total_cves": total_cves,
        "com_cvss": com_cvss,
        "sem_cvss": sem_cvss,
        "percentual_com_cvss": round(
            com_cvss / total_cves * 100, 2
        ) if total_cves else 0
    },
    "versoes_selecionadas": dict(versoes),
    "severidades_selecionadas": dict(severidades),
    "tipos_selecionados": dict(tipos),
    "fontes_selecionadas": dict(fontes),
    "validacoes": {
        "contagens_consistentes": True,
        "coerencia_pontuacao_severidade": (
            "Validada separadamente na etapa 4.10"
        ),
        "impacto_prioridade_versao": (
            "Documentado na etapa 4.11"
        )
    }
}


# ==========================================
# SALVAR EM DOCS
# ==========================================

pasta_docs = Path("docs")
pasta_docs.mkdir(parents=True, exist_ok=True)

caminho_saida = (
    pasta_docs / "auditoria_cvss_nvd.json"
)

with caminho_saida.open(
    "w",
    encoding="utf-8"
) as arquivo:
    json.dump(
        relatorio,
        arquivo,
        indent=2,
        ensure_ascii=False
    )


# ==========================================
# RESULTADO
# ==========================================

print("Coleta:", pasta_coleta.name)
print("Total de CVEs:", total_cves)
print("Com CVSS:", com_cvss)
print("Sem CVSS:", sem_cvss)

print(
    "Percentual com CVSS:",
    relatorio["indicadores"]["percentual_com_cvss"],
    "%"
)

print("\nRelatório salvo em:")
print(caminho_saida)

print("\nConsolidação CVSS: OK")
