
from pathlib import Path

import pandas as pd


# ==========================================
# 1. DEFINIR CAMINHOS
# ==========================================

arquivo_silver = Path(
    "data/silver/nvd/silver_cwe.parquet"
)

pasta_gold = Path("data/gold/nvd")

arquivo_saida = pasta_gold / "dim_cwe.parquet"


# ==========================================
# 2. CARREGAR OS DADOS
# ==========================================

if not arquivo_silver.exists():
    raise FileNotFoundError(
        f"Arquivo não encontrado: {arquivo_silver}"
    )

df_silver = pd.read_parquet(
    arquivo_silver,
    columns=["cwe_id"]
)


# ==========================================
# 3. IDENTIFICAR CÓDIGOS ÚNICOS
# ==========================================

df_cwe = (
    df_silver[["cwe_id"]]
    .drop_duplicates()
    .sort_values("cwe_id")
    .reset_index(drop=True)
)

# Renomear para deixar claro que o campo
# representa o código oficial da CWE.
df_cwe = df_cwe.rename(
    columns={"cwe_id": "cwe_codigo"}
)

# Criar uma chave numérica para a dimensão.
df_cwe.insert(
    0,
    "cwe_id",
    range(1, len(df_cwe) + 1)
)


# ==========================================
# 4. VALIDAR A DIMENSÃO
# ==========================================

assert len(df_cwe) == 251
assert len(df_cwe.columns) == 2

assert df_cwe["cwe_id"].is_unique
assert df_cwe["cwe_codigo"].is_unique

assert df_cwe.notna().all().all()

assert set(df_cwe["cwe_id"]) == set(
    range(1, 252)
)

assert (
    df_cwe["cwe_codigo"]
    .astype(str)
    .str.fullmatch(r"CWE-\d+")
    .all()
)


# ==========================================
# 5. SALVAR NA GOLD
# ==========================================

pasta_gold.mkdir(
    parents=True,
    exist_ok=True
)

df_cwe.to_parquet(
    arquivo_saida,
    index=False
)


# ==========================================
# 6. RELATÓRIO
# ==========================================

print("\nCONSTRUÇÃO GOLD — DIM CWE")

print("Registros:", len(df_cwe))
print("Colunas:", len(df_cwe.columns))

print("\nPRIMEIROS CÓDIGOS CWE")

print(
    df_cwe.head(10).to_string(index=False)
)

print("\nArquivo gerado:", arquivo_saida)

print("\nGold Dim CWE: OK")
