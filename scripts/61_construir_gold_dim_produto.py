
from pathlib import Path

import pandas as pd


# ==========================================
# 1. DEFINIR CAMINHOS
# ==========================================

arquivo_silver = Path(
    "data/silver/nvd/silver_cpe.parquet"
)

pasta_gold = Path("data/gold/nvd")

arquivo_saida = pasta_gold / "dim_produto.parquet"


# ==========================================
# 2. CARREGAR OS DADOS
# ==========================================

if not arquivo_silver.exists():
    raise FileNotFoundError(
        f"Arquivo não encontrado: {arquivo_silver}"
    )

df_silver = pd.read_parquet(
    arquivo_silver,
    columns=["fabricante", "produto"]
)


# ==========================================
# 3. IDENTIFICAR PRODUTOS DISTINTOS
# ==========================================

df_produto = (
    df_silver[
        ["fabricante", "produto"]
    ]
    .drop_duplicates()
    .sort_values(
        ["fabricante", "produto"]
    )
    .reset_index(drop=True)
)


# ==========================================
# 4. CRIAR CHAVE NUMÉRICA
# ==========================================

df_produto.insert(
    0,
    "produto_id",
    range(1, len(df_produto) + 1)
)


# ==========================================
# 5. VALIDAR A DIMENSÃO
# ==========================================

assert len(df_produto) == 1009
assert len(df_produto.columns) == 3

assert df_produto["produto_id"].is_unique

assert not df_produto.duplicated(
    subset=["fabricante", "produto"]
).any()

assert df_produto.notna().all().all()

assert set(df_produto["produto_id"]) == set(
    range(1, 1010)
)

assert df_produto["fabricante"].nunique() == 45


# ==========================================
# 6. SALVAR NA GOLD
# ==========================================

pasta_gold.mkdir(
    parents=True,
    exist_ok=True
)

df_produto.to_parquet(
    arquivo_saida,
    index=False
)


# ==========================================
# 7. RELATÓRIO
# ==========================================

print("\nCONSTRUÇÃO GOLD — DIM PRODUTO")

print("Produtos distintos:", len(df_produto))

print(
    "Fabricantes distintos:",
    df_produto["fabricante"].nunique()
)

print("Colunas:", len(df_produto.columns))

print("\nPRIMEIROS PRODUTOS")

print(
    df_produto.head(10).to_string(index=False)
)

print("\nArquivo gerado:", arquivo_saida)

print("\nGold Dim Produto: OK")
