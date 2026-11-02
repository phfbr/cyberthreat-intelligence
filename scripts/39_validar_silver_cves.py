
from pathlib import Path

import pandas as pd


# ==========================================
# 1. LOCALIZAR ARQUIVO SILVER
# ==========================================

arquivo = Path(
    "data/silver/nvd/silver_cves.parquet"
)

if not arquivo.exists():
    raise FileNotFoundError(
        f"Arquivo não encontrado: {arquivo}"
    )


# ==========================================
# 2. LER O PARQUET
# ==========================================

df = pd.read_parquet(arquivo)


# ==========================================
# 3. VALIDAR ESTRUTURA
# ==========================================

colunas_esperadas = [
    "cve_id",
    "data_publicacao",
    "data_modificacao",
    "status_nvd",
    "flag_rejeitada",
    "descricao_en",
    "cvss_referencia_versao",
    "cvss_referencia_pontuacao",
    "cvss_referencia_severidade",
    "cvss_referencia_fonte",
    "cvss_referencia_tipo",
]

assert len(df) == 2743

assert list(df.columns) == colunas_esperadas

assert df["cve_id"].notna().all()

assert df["cve_id"].is_unique

assert df["data_publicacao"].notna().all()

assert df["data_modificacao"].notna().all()

assert df["descricao_en"].notna().all()

assert df["status_nvd"].notna().all()


# ==========================================
# 4. VALIDAR REGRAS DE NEGÓCIO
# ==========================================

assert (
    df["flag_rejeitada"]
    == df["status_nvd"].eq("Rejected")
).all()

assert int(df["flag_rejeitada"].sum()) == 17

com_cvss = int(
    df["cvss_referencia_pontuacao"]
    .notna()
    .sum()
)

sem_cvss = int(
    df["cvss_referencia_pontuacao"]
    .isna()
    .sum()
)

assert com_cvss == 2569
assert sem_cvss == 174

pontuacoes = df[
    "cvss_referencia_pontuacao"
].dropna()

assert pontuacoes.between(0, 10).all()


# ==========================================
# 5. RELATÓRIO
# ==========================================

print("\nVALIDAÇÃO SILVER — CVEs")

print("Registros:", len(df))
print("Colunas:", len(df.columns))
print("IDs únicos:", df["cve_id"].is_unique)

print(
    "CVEs rejeitadas:",
    int(df["flag_rejeitada"].sum())
)

print("Com CVSS:", com_cvss)
print("Sem CVSS:", sem_cvss)

print("\nTIPOS DE DADOS")

print(df.dtypes.to_string())

print("\nPRIMEIROS 5 REGISTROS")

print(
    df[
        [
            "cve_id",
            "data_publicacao",
            "status_nvd",
            "cvss_referencia_pontuacao",
            "cvss_referencia_severidade",
        ]
    ].head(5).to_string(index=False)
)

print("\nValidação Silver CVEs: OK")
