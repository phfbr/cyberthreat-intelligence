
from pathlib import Path

import pandas as pd


# ==========================================
# 1. LOCALIZAR O ARQUIVO GOLD
# ==========================================

arquivo = Path(
    "data/gold/nvd/fato_vulnerabilidade.parquet"
)

if not arquivo.exists():
    raise FileNotFoundError(
        f"Arquivo não encontrado: {arquivo}"
    )


# ==========================================
# 2. CARREGAR A TABELA
# ==========================================

df = pd.read_parquet(arquivo)


# ==========================================
# 3. VALIDAR ESTRUTURA
# ==========================================

colunas_esperadas = [
    "cve_id",
    "data_publicacao",
    "data_atualizacao",
    "status_nvd",
    "flag_rejeitada",
    "cvss_versao",
    "cvss_pontuacao",
    "cvss_severidade",
    "flag_possui_cvss",
    "flag_possui_cwe",
    "flag_possui_cpe",
]

assert list(df.columns) == colunas_esperadas

assert len(df) == 2743

assert df["cve_id"].notna().all()

assert df["cve_id"].is_unique

assert df["data_publicacao"].notna().all()

assert df["data_atualizacao"].notna().all()

assert df["status_nvd"].notna().all()


# ==========================================
# 4. VALIDAR INDICADORES
# ==========================================

assert int(df["flag_rejeitada"].sum()) == 17

assert int(df["flag_possui_cvss"].sum()) == 2569

assert int(df["flag_possui_cwe"].sum()) == 2516

assert int(df["flag_possui_cpe"].sum()) == 715

assert int(
    df["cvss_pontuacao"].notna().sum()
) == 2569

assert df["cvss_pontuacao"].dropna().between(
    0, 10
).all()

assert (
    df["flag_possui_cvss"]
    == df["cvss_pontuacao"].notna()
).all()


# ==========================================
# 5. VALIDAR DATAS
# ==========================================

assert pd.api.types.is_datetime64_any_dtype(
    df["data_publicacao"]
)

assert pd.api.types.is_datetime64_any_dtype(
    df["data_atualizacao"]
)


# ==========================================
# 6. RELATÓRIO
# ==========================================

print("\nVALIDAÇÃO GOLD — FATO VULNERABILIDADE")

print("Registros:", len(df))
print("Colunas:", len(df.columns))
print("CVEs únicas:", df["cve_id"].nunique())

print(
    "CVEs com CVSS:",
    int(df["flag_possui_cvss"].sum())
)

print(
    "CVEs com CWE:",
    int(df["flag_possui_cwe"].sum())
)

print(
    "CVEs com CPE:",
    int(df["flag_possui_cpe"].sum())
)

print(
    "CVEs rejeitadas:",
    int(df["flag_rejeitada"].sum())
)

print("\nTIPOS DE DADOS")

print(df.dtypes.to_string())

print("\nValidação Gold Fato Vulnerabilidade: OK")
