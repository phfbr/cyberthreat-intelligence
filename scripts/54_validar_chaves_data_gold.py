
from pathlib import Path

import pandas as pd


# ==========================================
# 1. LOCALIZAR OS ARQUIVOS
# ==========================================

pasta_gold = Path("data/gold/nvd")

arquivo_fato = (
    pasta_gold / "fato_vulnerabilidade.parquet"
)

arquivo_data = (
    pasta_gold / "dim_data.parquet"
)


# ==========================================
# 2. CARREGAR OS DADOS
# ==========================================

df_fato = pd.read_parquet(arquivo_fato)

df_data = pd.read_parquet(arquivo_data)


# ==========================================
# 3. VALIDAR ESTRUTURA
# ==========================================

assert len(df_fato) == 2743
assert len(df_fato.columns) == 13

assert df_fato["cve_id"].is_unique
assert df_fato["cve_id"].notna().all()

assert df_data["data_id"].is_unique


# ==========================================
# 4. VALIDAR CHAVES DE DATA
# ==========================================

colunas_data = [
    "data_publicacao_id",
    "data_atualizacao_id",
]

assert df_fato[colunas_data].notna().all().all()

publicacao_esperada = (
    df_fato["data_publicacao"]
    .dt.strftime("%Y%m%d")
    .astype(int)
)

atualizacao_esperada = (
    df_fato["data_atualizacao"]
    .dt.strftime("%Y%m%d")
    .astype(int)
)

assert (
    df_fato["data_publicacao_id"]
    == publicacao_esperada
).all()

assert (
    df_fato["data_atualizacao_id"]
    == atualizacao_esperada
).all()


# ==========================================
# 5. VALIDAR CORRESPONDÊNCIA
# ==========================================

ids_calendario = set(df_data["data_id"])

publicacoes_fora = int(
    (~df_fato["data_publicacao_id"].isin(
        ids_calendario
    )).sum()
)

atualizacoes_fora = int(
    (~df_fato["data_atualizacao_id"].isin(
        ids_calendario
    )).sum()
)

assert publicacoes_fora == 0
assert atualizacoes_fora == 0


# ==========================================
# 6. VALIDAR INDICADORES ORIGINAIS
# ==========================================

assert int(df_fato["flag_possui_cvss"].sum()) == 2569
assert int(df_fato["flag_possui_cwe"].sum()) == 2516
assert int(df_fato["flag_possui_cpe"].sum()) == 715
assert int(df_fato["flag_rejeitada"].sum()) == 17


# ==========================================
# 7. RELATÓRIO FINAL
# ==========================================

print("\nVALIDAÇÃO GOLD — CHAVES DE DATA")

print("CVEs:", len(df_fato))
print("Colunas:", len(df_fato.columns))

print(
    "Publicações sem correspondência:",
    publicacoes_fora
)

print(
    "Atualizações sem correspondência:",
    atualizacoes_fora
)

print("\nINDICADORES PRESERVADOS")

print(
    "CVEs com CVSS:",
    int(df_fato["flag_possui_cvss"].sum())
)

print(
    "CVEs com CWE:",
    int(df_fato["flag_possui_cwe"].sum())
)

print(
    "CVEs com CPE:",
    int(df_fato["flag_possui_cpe"].sum())
)

print(
    "CVEs rejeitadas:",
    int(df_fato["flag_rejeitada"].sum())
)

print("\nValidação Chaves de Data Gold: OK")
