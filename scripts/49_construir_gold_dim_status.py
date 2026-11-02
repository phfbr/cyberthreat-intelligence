
from pathlib import Path

import pandas as pd


# ==========================================
# 1. DEFINIR CAMINHOS
# ==========================================

pasta_gold = Path("data/gold/nvd")

arquivo_fato = (
    pasta_gold / "fato_vulnerabilidade.parquet"
)

arquivo_saida = (
    pasta_gold / "dim_status.parquet"
)


# ==========================================
# 2. CARREGAR STATUS DA TABELA FATO
# ==========================================

df_fato = pd.read_parquet(
    arquivo_fato,
    columns=["status_nvd"]
)


# ==========================================
# 3. CRIAR A DIMENSÃO
# ==========================================

df_status = (
    df_fato[["status_nvd"]]
    .drop_duplicates()
    .sort_values("status_nvd")
    .reset_index(drop=True)
)

# Chave técnica da dimensão
df_status.insert(
    0,
    "status_id",
    range(1, len(df_status) + 1)
)


# ==========================================
# 4. VALIDAR
# ==========================================

assert len(df_status) == 7

assert df_status["status_id"].is_unique

assert df_status["status_nvd"].is_unique

assert df_status["status_nvd"].notna().all()

assert df_fato["status_nvd"].isin(
    df_status["status_nvd"]
).all()


# ==========================================
# 5. SALVAR
# ==========================================

df_status.to_parquet(
    arquivo_saida,
    index=False
)


# ==========================================
# 6. RELATÓRIO
# ==========================================

print("\nCONSTRUÇÃO GOLD — DIM STATUS")

print("Registros:", len(df_status))
print("Colunas:", len(df_status.columns))

print("\nSTATUS IDENTIFICADOS")

print(df_status.to_string(index=False))

print("\nArquivo gerado:", arquivo_saida)

print("\nGold Dim Status: OK")
