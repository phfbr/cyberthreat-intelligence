
from pathlib import Path

import pandas as pd


# ==========================================
# 1. DEFINIR CAMINHOS
# ==========================================

pasta_silver = Path("data/silver/nvd")
pasta_gold = Path("data/gold/nvd")

arquivo_silver = pasta_silver / "silver_cvss.parquet"

arquivo_fato = (
    pasta_gold / "fato_vulnerabilidade.parquet"
)

arquivo_saida = (
    pasta_gold / "fato_avaliacao_cvss.parquet"
)


# ==========================================
# 2. CARREGAR OS DADOS
# ==========================================

df_cvss = pd.read_parquet(arquivo_silver)

df_fato = pd.read_parquet(
    arquivo_fato,
    columns=["cve_id", "flag_possui_cvss"],
)


# ==========================================
# 3. VALIDAR DADOS DE ORIGEM
# ==========================================

assert len(df_cvss) == 3372
assert len(df_fato) == 2743

assert df_fato["cve_id"].is_unique

assert df_cvss["cve_id"].nunique() == 2569

assert int(
    df_cvss["flag_cvss_referencia"].sum()
) == 2569


# ==========================================
# 4. CRIAR IDENTIFICADOR DA AVALIAÇÃO
# ==========================================

# Preservamos a ordem original da Silver.
df_gold = df_cvss.copy()

df_gold.insert(
    0,
    "avaliacao_cvss_id",
    range(1, len(df_gold) + 1),
)


# ==========================================
# 5. VALIDAR A ESTRUTURA
# ==========================================

assert len(df_gold) == 3372
assert len(df_gold.columns) == 11

assert df_gold["avaliacao_cvss_id"].is_unique

assert df_gold["cve_id"].isin(
    df_fato["cve_id"]
).all()

assert df_gold["pontuacao"].between(
    0, 10
).all()

assert df_gold["versao_cvss"].notna().all()

assert df_gold["flag_cvss_referencia"].notna().all()


# ==========================================
# 6. VALIDAR AVALIAÇÕES DE REFERÊNCIA
# ==========================================

referencias = df_gold.loc[
    df_gold["flag_cvss_referencia"].astype(bool)
]

assert len(referencias) == 2569

assert referencias["cve_id"].is_unique

cves_com_cvss = set(
    df_fato.loc[
        df_fato["flag_possui_cvss"].astype(bool),
        "cve_id",
    ]
)

assert set(referencias["cve_id"]) == cves_com_cvss


# ==========================================
# 7. SALVAR NA GOLD
# ==========================================

pasta_gold.mkdir(
    parents=True,
    exist_ok=True,
)

df_gold.to_parquet(
    arquivo_saida,
    index=False,
)


# ==========================================
# 8. RELATÓRIO
# ==========================================

print("\nCONSTRUÇÃO GOLD — FATO AVALIAÇÃO CVSS")

print("Avaliações:", len(df_gold))

print(
    "CVEs com avaliações:",
    df_gold["cve_id"].nunique()
)

print(
    "Avaliações de referência:",
    len(referencias)
)

print("Colunas:", len(df_gold.columns))

print("\nDISTRIBUIÇÃO POR VERSÃO")

print(
    df_gold["versao_cvss"]
    .value_counts()
    .to_string()
)

print("\nArquivo gerado:", arquivo_saida)

print("\nGold Fato Avaliação CVSS: OK")
