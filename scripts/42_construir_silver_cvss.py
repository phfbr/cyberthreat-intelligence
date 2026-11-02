
import json
import math
from pathlib import Path

import pandas as pd

from cvss_selecao import selecionar_cvss_referencia
from nvd_coletas import selecionar_coleta_concluida


# ==========================================
# 1. CONFIGURAÇÕES
# ==========================================

VERSOES = {
    "cvssMetricV40": "4.0",
    "cvssMetricV31": "3.1",
    "cvssMetricV30": "3.0",
    "cvssMetricV2": "2.0",
}

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
# 2. EXTRAIR AVALIAÇÕES CVSS
# ==========================================

registros = []
total_cves = 0
cves_com_cvss = 0

for caminho in arquivos:

    with caminho.open(
        "r",
        encoding="utf-8"
    ) as arquivo:
        dados = json.load(arquivo)

    for item in dados["vulnerabilities"]:

        cve = item["cve"]
        cve_id = cve["id"]
        total_cves += 1

        metrics = cve.get("metrics") or {}

        referencia = selecionar_cvss_referencia(
            metrics
        )

        if referencia is not None:
            cves_com_cvss += 1

        avaliacoes_cve = []

        for chave, versao in VERSOES.items():

            for indice, metrica in enumerate(
                metrics.get(chave) or []
            ):

                dados_cvss = metrica.get(
                    "cvssData"
                ) or {}

                pontuacao = dados_cvss.get(
                    "baseScore"
                )

                if (
                    not isinstance(
                        pontuacao,
                        (int, float)
                    )
                    or isinstance(pontuacao, bool)
                    or not math.isfinite(pontuacao)
                    or not 0 <= pontuacao <= 10
                ):
                    continue

                avaliacoes_cve.append({
                    "cve_id": cve_id,
                    "versao_cvss": versao,
                    "pontuacao": float(pontuacao),
                    "severidade": (
                        dados_cvss.get("baseSeverity")
                        or metrica.get("baseSeverity")
                    ),
                    "fonte": metrica.get("source"),
                    "tipo": metrica.get("type"),
                    "vetor": dados_cvss.get(
                        "vectorString"
                    ),
                    "chave_metrica": chave,
                    "indice_origem": indice,
                    "flag_cvss_referencia": False,
                })

        # Identificar a avaliação de referência
        if referencia is not None:

            candidatos = [
                registro
                for registro in avaliacoes_cve
                if (
                    registro["versao_cvss"]
                    == referencia["versao"]
                    and registro["pontuacao"]
                    == referencia["pontuacao"]
                    and registro["fonte"]
                    == referencia["fonte"]
                    and registro["tipo"]
                    == referencia["tipo"]
                    and registro["vetor"]
                    == referencia["vetor"]
                )
            ]

            if not candidatos:
                raise ValueError(
                    f"CVSS de referência não encontrado: {cve_id}"
                )

            # Em caso de avaliações idênticas,
            # marcar apenas uma ocorrência.
            candidatos[0][
                "flag_cvss_referencia"
            ] = True

        registros.extend(avaliacoes_cve)


# ==========================================
# 3. CRIAR DATAFRAME
# ==========================================

df = pd.DataFrame(registros)

df["pontuacao"] = pd.to_numeric(
    df["pontuacao"],
    errors="raise"
)

df["flag_cvss_referencia"] = (
    df["flag_cvss_referencia"].astype(bool)
)


# ==========================================
# 4. VALIDAÇÕES
# ==========================================

assert total_cves == 2743

assert cves_com_cvss == 2569

assert len(df) == 3372

assert df["pontuacao"].between(0, 10).all()

assert (
    int(df["flag_cvss_referencia"].sum())
    == cves_com_cvss
)

assert (
    df.loc[
        df["flag_cvss_referencia"],
        "cve_id"
    ].is_unique
)

arquivo_cves = Path(
    "data/silver/nvd/silver_cves.parquet"
)

df_cves = pd.read_parquet(
    arquivo_cves,
    columns=["cve_id"]
)

assert df["cve_id"].isin(
    df_cves["cve_id"]
).all()


# ==========================================
# 5. SALVAR NA SILVER
# ==========================================

pasta_saida = Path("data/silver/nvd")
pasta_saida.mkdir(
    parents=True,
    exist_ok=True
)

arquivo_saida = (
    pasta_saida / "silver_cvss.parquet"
)

df.to_parquet(
    arquivo_saida,
    index=False
)


# ==========================================
# 6. RELATÓRIO
# ==========================================

print("Coleta:", pasta_coleta.name)

print("\nCONSTRUÇÃO SILVER — CVSS")

print("CVEs analisadas:", total_cves)
print("Avaliações CVSS:", len(df))
print("CVEs com CVSS:", cves_com_cvss)

print(
    "Avaliações de referência:",
    int(df["flag_cvss_referencia"].sum())
)

print("\nAVALIAÇÕES POR VERSÃO")

print(
    df["versao_cvss"]
    .value_counts()
    .sort_index()
    .to_string()
)

print("\nAVALIAÇÕES POR TIPO")

print(
    df["tipo"]
    .value_counts(dropna=False)
    .to_string()
)

print("\nArquivo gerado:", arquivo_saida)

print("\nSilver CVSS: OK")
