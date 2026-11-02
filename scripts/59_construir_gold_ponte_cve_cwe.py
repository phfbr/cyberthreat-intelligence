
from pathlib import Path

import pandas as pd


# ==========================================
# 1. DEFINIR CAMINHOS
# ==========================================

pasta_silver = Path("data/silver/nvd")
pasta_gold = Path("data/gold/nvd")

arquivo_silver = pasta_silver / "silver_cwe.parquet"
arquivo_dim_cwe = pasta_gold / "dim_cwe.parquet"
arquivo_fato = pasta_gold / "fato_vulnerabilidade.parquet"

arquivo_saida = pasta_gold / "ponte_cve_cwe.parquet"


# ==========================================
# 2. CARREGAR OS DADOS
# ==========================================

df_silver = pd.read_parquet(
    arquivo_silver,
    columns=["cve_id", "cwe_id"]
)

df_dim_cwe = pd.read_parquet(
    arquivo_dim_cwe,
    columns=["cwe_id", "cwe_codigo"]
)

df_fato = pd.read_parquet(
    arquivo_fato,
    columns=["cve_id"]
)


# ==========================================
# 3. VERIFICAR DADOS DE ORIGEM
# ==========================================

assert len(df_silver) == 2968
assert len(df_dim_cwe) == 251
assert len(df_fato) == 2743

assert df_fato["cve_id"].is_unique
assert df_dim_cwe["cwe_id"].is_unique
assert df_dim_cwe["cwe_codigo"].is_unique

assert not df_silver.duplicated(
    subset=["cve_id", "cwe_id"]
).any()


# ==========================================
# 4. RELACIONAR A DIMENSÃO CWE
# ==========================================

# Na Silver, cwe_id contém o código oficial.
# Na Gold, cwe_id é a chave numérica.

df_ponte = df_silver.merge(
    df_dim_cwe,
    left_on="cwe_id",
    right_on="cwe_codigo",
    how="left",
    validate="many_to_one",
    indicator=True,
    suffixes=("_silver", "_gold"),
)

sem_cwe = int(
    (df_ponte["_merge"] != "both").sum()
)

assert sem_cwe == 0

df_ponte = df_ponte.rename(
    columns={"cwe_id_gold": "cwe_id"}
)

df_ponte = df_ponte[
    ["cve_id", "cwe_id"]
]


# ==========================================
# 5. VALIDAR AS CHAVES
# ==========================================

assert len(df_ponte) == 2968

assert df_ponte.notna().all().all()

assert not df_ponte.duplicated(
    subset=["cve_id", "cwe_id"]
).any()

assert df_ponte["cve_id"].isin(
    df_fato["cve_id"]
).all()

assert df_ponte["cwe_id"].isin(
    df_dim_cwe["cwe_id"]
).all()

assert df_ponte["cve_id"].nunique() == 2516
assert df_ponte["cwe_id"].nunique() == 251


# ==========================================
# 6. ORGANIZAR E SALVAR
# ==========================================

df_ponte = (
    df_ponte
    .sort_values(["cve_id", "cwe_id"])
    .reset_index(drop=True)
)

df_ponte["cwe_id"] = (
    df_ponte["cwe_id"].astype(int)
)

pasta_gold.mkdir(
    parents=True,
    exist_ok=True
)

df_ponte.to_parquet(
    arquivo_saida,
    index=False
)


# ==========================================
# 7. RELATÓRIO
# ==========================================

print("\nCONSTRUÇÃO GOLD — PONTE CVE CWE")

print("Associações:", len(df_ponte))
print("CVEs distintas:", df_ponte["cve_id"].nunique())
print("CWEs distintas:", df_ponte["cwe_id"].nunique())

print("Associações sem CWE:", sem_cwe)

print("\nPRIMEIRAS LINHAS")
print(df_ponte.head(10).to_string(index=False))

print("\nArquivo gerado:", arquivo_saida)

print("\nGold Ponte CVE CWE: OK")
