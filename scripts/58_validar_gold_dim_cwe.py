
from pathlib import Path

import pandas as pd


# ==========================================
# 1. LOCALIZAR OS ARQUIVOS
# ==========================================

arquivo_silver = Path(
    "data/silver/nvd/silver_cwe.parquet"
)

arquivo_gold = Path(
    "data/gold/nvd/dim_cwe.parquet"
)

for arquivo in [arquivo_silver, arquivo_gold]:
    if not arquivo.exists():
        raise FileNotFoundError(
            f"Arquivo não encontrado: {arquivo}"
        )


# ==========================================
# 2. CARREGAR OS DADOS
# ==========================================

df_silver = pd.read_parquet(
    arquivo_silver,
    columns=["cwe_id"]
)

df_gold = pd.read_parquet(arquivo_gold)


# ==========================================
# 3. VALIDAR ESTRUTURA GOLD
# ==========================================

assert list(df_gold.columns) == [
    "cwe_id",
    "cwe_codigo",
]

assert len(df_gold) == 251

assert df_gold["cwe_id"].is_unique
assert df_gold["cwe_codigo"].is_unique

assert df_gold.notna().all().all()

assert set(df_gold["cwe_id"]) == set(
    range(1, 252)
)


# ==========================================
# 4. VALIDAR CÓDIGOS CWE
# ==========================================

assert (
    df_gold["cwe_codigo"]
    .astype(str)
    .str.fullmatch(r"CWE-\d+")
    .all()
)

codigos_silver = set(
    df_silver["cwe_id"].dropna()
)

codigos_gold = set(
    df_gold["cwe_codigo"]
)

codigos_ausentes = (
    codigos_silver - codigos_gold
)

codigos_extras = (
    codigos_gold - codigos_silver
)

assert len(codigos_ausentes) == 0
assert len(codigos_extras) == 0


# ==========================================
# 5. VALIDAR ASSOCIAÇÕES
# ==========================================

associacoes_silver = len(
    pd.read_parquet(
        arquivo_silver,
        columns=["cwe_id"]
    )
)

assert associacoes_silver == 2968


# ==========================================
# 6. RELATÓRIO
# ==========================================

print("\nVALIDAÇÃO GOLD — DIM CWE")

print("Códigos CWE:", len(df_gold))
print("Colunas:", len(df_gold.columns))

print(
    "Códigos ausentes:",
    len(codigos_ausentes)
)

print(
    "Códigos extras:",
    len(codigos_extras)
)

print(
    "Associações na Silver:",
    associacoes_silver
)

print("\nValidação Gold Dim CWE: OK")
