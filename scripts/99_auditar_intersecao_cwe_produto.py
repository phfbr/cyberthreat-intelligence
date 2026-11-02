
from pathlib import Path
import pandas as pd

# Diretório principal do projeto
ROOT = Path(__file__).resolve().parents[1]

# Arquivos Gold
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

# 1. Identificar o ID da CWE-79
cwe_selecionada = dim_cwe[
    dim_cwe["cwe_codigo"] == "CWE-79"
]

if cwe_selecionada.empty:
    raise ValueError("CWE-79 não encontrada na dimensão.")

cwe_id = cwe_selecionada["cwe_id"].iloc[0]

# 2. Identificar CVEs associadas à CWE-79
cves_cwe = set(
    ponte_cwe.loc[
        ponte_cwe["cwe_id"] == cwe_id,
        "cve_id"
    ].unique()
)

# 3. Identificar produtos do fabricante Apache
produtos_apache = dim_produto[
    dim_produto["fabricante"]
    .str.strip()
    .str.lower() == "apache"
]

if produtos_apache.empty:
    raise ValueError("Fabricante Apache não encontrado.")

ids_produtos_apache = set(
    produtos_apache["produto_id"]
)

# 4. Identificar CVEs associadas ao Apache
cves_apache = set(
    ponte_produto.loc[
        ponte_produto["produto_id"].isin(
            ids_produtos_apache
        ),
        "cve_id"
    ].unique()
)

# 5. Calcular a interseção
cves_intersecao = cves_cwe.intersection(
    cves_apache
)

# 6. Exibir resultados
print("\nAUDITORIA CWE-79 x APACHE")
print("=" * 45)

print(f"CVEs associadas à CWE-79: {len(cves_cwe)}")
print(f"Produtos Apache: {len(ids_produtos_apache)}")
print(f"CVEs associadas ao Apache: {len(cves_apache)}")

print("-" * 45)

print(f"CVEs em comum: {len(cves_intersecao)}")

print("\nAMOSTRA DAS CVEs EM COMUM")

for cve in sorted(cves_intersecao)[:10]:
    print(cve)

print("\nAUDITORIA CONCLUÍDA.")
