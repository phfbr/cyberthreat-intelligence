
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

# Carregar arquivos Gold
dim_cwe = pd.read_parquet(
    ROOT / "data/gold/nvd/dim_cwe.parquet"
)

ponte_cwe = pd.read_parquet(
    ROOT / "data/gold/nvd/ponte_cve_cwe.parquet"
)

dim_produto = pd.read_parquet(
    ROOT / "data/gold/nvd/dim_produto.parquet"
)

ponte_produto = pd.read_parquet(
    ROOT / "data/gold/nvd/ponte_cve_produto.parquet"
)

# Associar CVEs aos códigos CWE
cwe = ponte_cwe.merge(
    dim_cwe[["cwe_id", "cwe_codigo"]],
    on="cwe_id",
    how="inner"
)

# Associar CVEs aos fabricantes
produto = ponte_produto.merge(
    dim_produto[["produto_id", "fabricante"]],
    on="produto_id",
    how="inner"
)

# Eliminar associações repetidas
cwe = cwe[["cve_id", "cwe_codigo"]].drop_duplicates()

produto = produto[
    ["cve_id", "fabricante"]
].drop_duplicates()

# Encontrar CVEs presentes nas duas estruturas
intersecao = cwe.merge(
    produto,
    on="cve_id",
    how="inner"
)

# Contabilizar CVEs distintas por combinação
resultado = (
    intersecao
    .groupby(["cwe_codigo", "fabricante"])
    .agg(
        quantidade_cves=("cve_id", "nunique")
    )
    .reset_index()
    .sort_values(
        "quantidade_cves",
        ascending=False
    )
)

print("\nTOP 10 — INTERSEÇÕES CWE x FABRICANTE")
print("=" * 55)

print(resultado.head(10).to_string(index=False))

if not resultado.empty:
    melhor = resultado.iloc[0]

    print("\nCOMBINAÇÃO SELECIONADA")
    print("-" * 55)
    print(f"CWE: {melhor['cwe_codigo']}")
    print(f"Fabricante: {melhor['fabricante']}")
    print(f"CVEs em comum: {melhor['quantidade_cves']}")

print("\nAUDITORIA CONCLUÍDA.")
