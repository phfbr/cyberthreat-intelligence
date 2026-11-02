
from pathlib import Path

import pandas as pd


# ==========================================
# 1. DEFINIR CAMINHOS
# ==========================================

pasta_silver = Path("data/silver/nvd")
pasta_gold = Path("data/gold/nvd")

arquivo_silver = pasta_silver / "silver_cvss.parquet"

arquivo_gold = (
    pasta_gold / "fato_avaliacao_cvss.parquet"
)

arquivo_fato = (
    pasta_gold / "fato_vulnerabilidade.parquet"
)


# ==========================================
# 2. CARREGAR OS DADOS
# ==========================================

df_silver = pd.read_parquet(arquivo_silver)
df_gold = pd.read_parquet(arquivo_gold)

df_fato = pd.read_parquet(
    arquivo_fato,
    columns=[
        "cve_id",
        "flag_possui_cvss",
        "cvss_versao",
        "cvss_pontuacao",
        "cvss_severidade",
    ],
)


# ==========================================
# 3. VALIDAR ESTRUTURA
# ==========================================

assert len(df_silver) == 3372
assert len(df_gold) == 3372

assert len(df_gold.columns) == 11

assert df_gold["avaliacao_cvss_id"].is_unique
assert df_gold["avaliacao_cvss_id"].notna().all()

assert set(df_gold.columns) == (
    set(df_silver.columns) | {"avaliacao_cvss_id"}
)

assert df_gold["cve_id"].nunique() == 2569

assert df_gold["pontuacao"].between(0, 10).all()


# ==========================================
# 4. COMPARAR SILVER E GOLD
# ==========================================

colunas_originais = list(df_silver.columns)

pd.testing.assert_frame_equal(
    df_gold[colunas_originais].reset_index(drop=True),
    df_silver.reset_index(drop=True),
    check_dtype=True,
)


# ==========================================
# 5. VALIDAR CHAVES ESTRANGEIRAS
# ==========================================

cves_invalidas = int(
    (~df_gold["cve_id"].isin(
        df_fato["cve_id"]
    )).sum()
)

assert cves_invalidas == 0


# ==========================================
# 6. VALIDAR AVALIAÇÕES DE REFERÊNCIA
# ==========================================

df_referencia = df_gold.loc[
    df_gold["flag_cvss_referencia"].astype(bool)
].copy()

assert len(df_referencia) == 2569

assert df_referencia["cve_id"].is_unique

cves_com_cvss = set(
    df_fato.loc[
        df_fato["flag_possui_cvss"].astype(bool),
        "cve_id",
    ]
)

assert set(df_referencia["cve_id"]) == cves_com_cvss


# ==========================================
# 7. CONFERIR REFERÊNCIA COM A FATO
# ==========================================

df_comparacao = df_referencia.merge(
    df_fato,
    on="cve_id",
    how="left",
    validate="one_to_one",
)

assert (
    df_comparacao["versao_cvss"].astype(str)
    == df_comparacao["cvss_versao"].astype(str)
).all()

assert (
    df_comparacao["pontuacao"]
    == df_comparacao["cvss_pontuacao"]
).all()

assert (
    df_comparacao["severidade"].fillna("")
    == df_comparacao["cvss_severidade"].fillna("")
).all()


# ==========================================
# 8. VALIDAR DISTRIBUIÇÃO POR VERSÃO
# ==========================================

versoes_esperadas = {
    "3.1": 2309,
    "4.0": 903,
    "2.0": 154,
    "3.0": 6,
}

versoes_reais = (
    df_gold["versao_cvss"]
    .astype(str)
    .value_counts()
    .to_dict()
)

assert versoes_reais == versoes_esperadas


# ==========================================
# 9. RELATÓRIO
# ==========================================

print("\nVALIDAÇÃO GOLD — FATO AVALIAÇÃO CVSS")

print("Avaliações:", len(df_gold))
print("CVEs distintas:", df_gold["cve_id"].nunique())

print(
    "Avaliações de referência:",
    len(df_referencia)
)

print("CVEs inválidas:", cves_invalidas)

print("Silver e Gold: idênticas nos campos originais")

print("Referências compatíveis com a fato: OK")

print("\nValidação Gold Fato Avaliação CVSS: OK")
