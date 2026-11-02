
from pathlib import Path

import pandas as pd


# ==========================================
# 1. DEFINIR CAMINHOS
# ==========================================

pasta_silver = Path("data/silver/nvd")
pasta_gold = Path("data/gold/nvd")

arquivo_silver = pasta_silver / "silver_cwe.parquet"
arquivo_fato = pasta_gold / "fato_vulnerabilidade.parquet"
arquivo_dim = pasta_gold / "dim_cwe.parquet"
arquivo_ponte = pasta_gold / "ponte_cve_cwe.parquet"


# ==========================================
# 2. CARREGAR AS TABELAS
# ==========================================

df_silver = pd.read_parquet(arquivo_silver)

df_fato = pd.read_parquet(
    arquivo_fato,
    columns=["cve_id", "flag_possui_cwe"]
)

df_dim = pd.read_parquet(arquivo_dim)

df_ponte = pd.read_parquet(arquivo_ponte)


# ==========================================
# 3. VALIDAR ESTRUTURA
# ==========================================

assert list(df_ponte.columns) == [
    "cve_id",
    "cwe_id",
]

assert len(df_ponte) == 2968
assert df_ponte["cve_id"].nunique() == 2516
assert df_ponte["cwe_id"].nunique() == 251

assert df_ponte.notna().all().all()

assert not df_ponte.duplicated(
    subset=["cve_id", "cwe_id"]
).any()


# ==========================================
# 4. VALIDAR CHAVES ESTRANGEIRAS
# ==========================================

cves_sem_correspondencia = int(
    (~df_ponte["cve_id"].isin(
        df_fato["cve_id"]
    )).sum()
)

cwes_sem_correspondencia = int(
    (~df_ponte["cwe_id"].isin(
        df_dim["cwe_id"]
    )).sum()
)

assert cves_sem_correspondencia == 0
assert cwes_sem_correspondencia == 0


# ==========================================
# 5. RECONSTRUIR OS CÓDIGOS ORIGINAIS
# ==========================================

df_reconstruido = df_ponte.merge(
    df_dim,
    on="cwe_id",
    how="left",
    validate="many_to_one",
)

pares_silver = set(
    zip(
        df_silver["cve_id"],
        df_silver["cwe_id"],
    )
)

pares_gold = set(
    zip(
        df_reconstruido["cve_id"],
        df_reconstruido["cwe_codigo"],
    )
)

associacoes_ausentes = pares_silver - pares_gold
associacoes_extras = pares_gold - pares_silver

assert len(associacoes_ausentes) == 0
assert len(associacoes_extras) == 0


# ==========================================
# 6. VALIDAR INDICADOR DA FATO
# ==========================================

cves_com_cwe = set(df_ponte["cve_id"])

flags_esperadas = df_fato["cve_id"].isin(
    cves_com_cwe
)

assert (
    df_fato["flag_possui_cwe"].astype(bool)
    == flags_esperadas
).all()


# ==========================================
# 7. RELATÓRIO
# ==========================================

print("\nVALIDAÇÃO GOLD — PONTE CVE CWE")

print("Associações:", len(df_ponte))
print("CVEs distintas:", df_ponte["cve_id"].nunique())
print("CWEs distintas:", df_ponte["cwe_id"].nunique())

print(
    "CVEs sem correspondência:",
    cves_sem_correspondencia
)

print(
    "CWEs sem correspondência:",
    cwes_sem_correspondencia
)

print(
    "Associações ausentes:",
    len(associacoes_ausentes)
)

print(
    "Associações extras:",
    len(associacoes_extras)
)

print("\nValidação Gold Ponte CVE CWE: OK")
