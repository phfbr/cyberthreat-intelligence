
from pathlib import Path

import pandas as pd


# ==========================================
# 1. DEFINIR CAMINHOS
# ==========================================

pasta_silver = Path("data/silver/nvd")
pasta_gold = Path("data/gold/nvd")

arquivo_cpe = pasta_silver / "silver_cpe.parquet"
arquivo_produto = pasta_gold / "dim_produto.parquet"
arquivo_fato = pasta_gold / "fato_vulnerabilidade.parquet"

arquivo_saida = pasta_gold / "ponte_cve_produto.parquet"


# ==========================================
# 2. CARREGAR OS DADOS
# ==========================================

df_cpe = pd.read_parquet(
    arquivo_cpe,
    columns=[
        "cve_id",
        "fabricante",
        "produto",
    ],
)

df_produto = pd.read_parquet(
    arquivo_produto,
    columns=[
        "produto_id",
        "fabricante",
        "produto",
    ],
)

df_fato = pd.read_parquet(
    arquivo_fato,
    columns=[
        "cve_id",
        "flag_possui_cpe",
    ],
)


# ==========================================
# 3. VALIDAR DADOS DE ORIGEM
# ==========================================

assert len(df_cpe) == 8180
assert len(df_produto) == 1009
assert len(df_fato) == 2743

assert df_fato["cve_id"].is_unique
assert df_produto["produto_id"].is_unique

assert not df_produto.duplicated(
    subset=["fabricante", "produto"]
).any()


# ==========================================
# 4. IDENTIFICAR ASSOCIAÇÕES DISTINTAS
# ==========================================

df_associacoes = (
    df_cpe[
        ["cve_id", "fabricante", "produto"]
    ]
    .drop_duplicates()
    .reset_index(drop=True)
)


# ==========================================
# 5. RELACIONAR COM DIM PRODUTO
# ==========================================

df_ponte = df_associacoes.merge(
    df_produto,
    on=["fabricante", "produto"],
    how="left",
    validate="many_to_one",
    indicator=True,
)

sem_produto = int(
    (df_ponte["_merge"] != "both").sum()
)

assert sem_produto == 0

df_ponte = df_ponte[
    ["cve_id", "produto_id"]
].copy()


# ==========================================
# 6. VALIDAR A TABELA PONTE
# ==========================================

assert len(df_ponte) == len(df_associacoes)

assert df_ponte.notna().all().all()

assert not df_ponte.duplicated(
    subset=["cve_id", "produto_id"]
).any()

assert df_ponte["cve_id"].isin(
    df_fato["cve_id"]
).all()

assert df_ponte["produto_id"].isin(
    df_produto["produto_id"]
).all()

assert df_ponte["cve_id"].nunique() == 715

cves_com_cpe = set(
    df_fato.loc[
        df_fato["flag_possui_cpe"].astype(bool),
        "cve_id",
    ]
)

assert set(df_ponte["cve_id"]) == cves_com_cpe


# ==========================================
# 7. ORGANIZAR E SALVAR
# ==========================================

df_ponte = (
    df_ponte
    .sort_values(["cve_id", "produto_id"])
    .reset_index(drop=True)
)

df_ponte["produto_id"] = (
    df_ponte["produto_id"].astype(int)
)

pasta_gold.mkdir(
    parents=True,
    exist_ok=True,
)

df_ponte.to_parquet(
    arquivo_saida,
    index=False,
)


# ==========================================
# 8. RELATÓRIO
# ==========================================

print("\nCONSTRUÇÃO GOLD — PONTE CVE PRODUTO")

print("Ocorrências CPE na Silver:", len(df_cpe))

print("Associações distintas:", len(df_ponte))

print(
    "CVEs distintas:",
    df_ponte["cve_id"].nunique()
)

print(
    "Produtos distintos:",
    df_ponte["produto_id"].nunique()
)

print("Associações sem produto:", sem_produto)

print("\nPRIMEIRAS LINHAS")

print(
    df_ponte.head(10).to_string(index=False)
)

print("\nArquivo gerado:", arquivo_saida)

print("\nGold Ponte CVE Produto: OK")
