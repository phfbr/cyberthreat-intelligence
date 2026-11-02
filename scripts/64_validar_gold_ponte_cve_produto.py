
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
arquivo_ponte = pasta_gold / "ponte_cve_produto.parquet"


# ==========================================
# 2. CARREGAR OS DADOS
# ==========================================

df_cpe = pd.read_parquet(
    arquivo_cpe,
    columns=["cve_id", "fabricante", "produto"],
)

df_produto = pd.read_parquet(arquivo_produto)

df_fato = pd.read_parquet(
    arquivo_fato,
    columns=["cve_id", "flag_possui_cpe"],
)

df_ponte = pd.read_parquet(arquivo_ponte)


# ==========================================
# 3. VALIDAR ESTRUTURA
# ==========================================

assert list(df_ponte.columns) == [
    "cve_id",
    "produto_id",
]

assert df_ponte.notna().all().all()

assert not df_ponte.duplicated(
    subset=["cve_id", "produto_id"]
).any()

assert df_ponte["cve_id"].nunique() == 715

assert df_fato["cve_id"].is_unique
assert df_produto["produto_id"].is_unique


# ==========================================
# 4. VALIDAR CHAVES ESTRANGEIRAS
# ==========================================

cves_invalidas = int(
    (~df_ponte["cve_id"].isin(
        df_fato["cve_id"]
    )).sum()
)

produtos_invalidos = int(
    (~df_ponte["produto_id"].isin(
        df_produto["produto_id"]
    )).sum()
)

assert cves_invalidas == 0
assert produtos_invalidos == 0


# ==========================================
# 5. RECONSTRUIR ASSOCIAÇÕES
# ==========================================

df_reconstruido = df_ponte.merge(
    df_produto[
        ["produto_id", "fabricante", "produto"]
    ],
    on="produto_id",
    how="left",
    validate="many_to_one",
)

pares_silver = set(
    zip(
        df_cpe["cve_id"],
        df_cpe["fabricante"],
        df_cpe["produto"],
    )
)

pares_gold = set(
    zip(
        df_reconstruido["cve_id"],
        df_reconstruido["fabricante"],
        df_reconstruido["produto"],
    )
)

associacoes_ausentes = pares_silver - pares_gold
associacoes_extras = pares_gold - pares_silver

assert len(associacoes_ausentes) == 0
assert len(associacoes_extras) == 0

assert len(df_ponte) == len(pares_silver)


# ==========================================
# 6. VALIDAR INDICADOR DA FATO
# ==========================================

cves_com_produto = set(df_ponte["cve_id"])

flags_esperadas = df_fato["cve_id"].isin(
    cves_com_produto
)

assert (
    df_fato["flag_possui_cpe"].astype(bool)
    == flags_esperadas
).all()


# ==========================================
# 7. RELATÓRIO
# ==========================================

print("\nVALIDAÇÃO GOLD — PONTE CVE PRODUTO")

print("Ocorrências CPE:", len(df_cpe))
print("Associações distintas:", len(df_ponte))
print("CVEs distintas:", df_ponte["cve_id"].nunique())

print(
    "Produtos distintos na ponte:",
    df_ponte["produto_id"].nunique()
)

print("CVEs inválidas:", cves_invalidas)
print("Produtos inválidos:", produtos_invalidos)

print(
    "Associações ausentes:",
    len(associacoes_ausentes)
)

print(
    "Associações extras:",
    len(associacoes_extras)
)

print("\nValidação Gold Ponte CVE Produto: OK")
