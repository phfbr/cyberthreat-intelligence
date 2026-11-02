
from pathlib import Path

import pandas as pd


# ==========================================
# 1. DEFINIR CAMINHOS
# ==========================================

arquivo_silver = Path(
    "data/silver/nvd/silver_cpe.parquet"
)

arquivo_gold = Path(
    "data/gold/nvd/dim_produto.parquet"
)


# ==========================================
# 2. CARREGAR OS DADOS
# ==========================================

df_silver = pd.read_parquet(
    arquivo_silver,
    columns=["fabricante", "produto"]
)

df_gold = pd.read_parquet(arquivo_gold)


# ==========================================
# 3. VALIDAR ESTRUTURA
# ==========================================

assert list(df_gold.columns) == [
    "produto_id",
    "fabricante",
    "produto",
]

assert len(df_gold) == 1009
assert len(df_gold.columns) == 3

assert df_gold["produto_id"].is_unique
assert df_gold.notna().all().all()

assert set(df_gold["produto_id"]) == set(
    range(1, 1010)
)

assert not df_gold.duplicated(
    subset=["fabricante", "produto"]
).any()


# ==========================================
# 4. COMPARAR SILVER E GOLD
# ==========================================

pares_silver = set(
    zip(
        df_silver["fabricante"],
        df_silver["produto"],
    )
)

pares_gold = set(
    zip(
        df_gold["fabricante"],
        df_gold["produto"],
    )
)

produtos_ausentes = pares_silver - pares_gold
produtos_extras = pares_gold - pares_silver

assert len(produtos_ausentes) == 0
assert len(produtos_extras) == 0


# ==========================================
# 5. VALIDAR FABRICANTES
# ==========================================

fabricantes_silver = set(
    df_silver["fabricante"]
)

fabricantes_gold = set(
    df_gold["fabricante"]
)

assert fabricantes_silver == fabricantes_gold
assert len(fabricantes_gold) == 45


# ==========================================
# 6. RELATÓRIO
# ==========================================

print("\nVALIDAÇÃO GOLD — DIM PRODUTO")

print("Produtos distintos:", len(df_gold))
print("Fabricantes distintos:", len(fabricantes_gold))

print(
    "Produtos ausentes:",
    len(produtos_ausentes)
)

print(
    "Produtos extras:",
    len(produtos_extras)
)

print(
    "Combinações duplicadas:",
    int(
        df_gold.duplicated(
            subset=["fabricante", "produto"]
        ).sum()
    )
)

print("\nValidação Gold Dim Produto: OK")
