
from pathlib import Path

import pandas as pd


# ==========================================
# 1. LOCALIZAR ARQUIVOS
# ==========================================

pasta = Path("data/silver/nvd")

arquivo_cvss = pasta / "silver_cvss.parquet"
arquivo_cves = pasta / "silver_cves.parquet"

for arquivo in [arquivo_cvss, arquivo_cves]:
    if not arquivo.exists():
        raise FileNotFoundError(
            f"Arquivo não encontrado: {arquivo}"
        )


# ==========================================
# 2. LER ARQUIVOS PARQUET
# ==========================================

df_cvss = pd.read_parquet(arquivo_cvss)
df_cves = pd.read_parquet(arquivo_cves)


# ==========================================
# 3. VALIDAR ESTRUTURA
# ==========================================

colunas_esperadas = [
    "cve_id",
    "versao_cvss",
    "pontuacao",
    "severidade",
    "fonte",
    "tipo",
    "vetor",
    "chave_metrica",
    "indice_origem",
    "flag_cvss_referencia",
]

assert list(df_cvss.columns) == colunas_esperadas

assert len(df_cvss) == 3372

assert df_cvss["cve_id"].notna().all()

assert df_cvss["pontuacao"].notna().all()

assert df_cvss["pontuacao"].between(
    0, 10
).all()

assert df_cvss["flag_cvss_referencia"].notna().all()


# ==========================================
# 4. VALIDAR INTEGRIDADE REFERENCIAL
# ==========================================

assert df_cves["cve_id"].is_unique

assert df_cvss["cve_id"].isin(
    df_cves["cve_id"]
).all()

# Identidade física de cada avaliação na origem
assert not df_cvss.duplicated(
    subset=[
        "cve_id",
        "chave_metrica",
        "indice_origem",
    ]
).any()


# ==========================================
# 5. VALIDAR AVALIAÇÕES DE REFERÊNCIA
# ==========================================

df_referencia = df_cvss.loc[
    df_cvss["flag_cvss_referencia"]
].copy()

assert len(df_referencia) == 2569

assert df_referencia["cve_id"].is_unique

assert df_cvss["cve_id"].nunique() == 2569


# ==========================================
# 6. COMPARAR COM SILVER_CVES
# ==========================================

comparacao = df_cves.merge(
    df_referencia[
        [
            "cve_id",
            "versao_cvss",
            "pontuacao",
            "severidade",
            "fonte",
            "tipo",
        ]
    ],
    on="cve_id",
    how="left",
    validate="one_to_one",
)

campos = [
    ("cvss_referencia_versao", "versao_cvss"),
    ("cvss_referencia_pontuacao", "pontuacao"),
    ("cvss_referencia_severidade", "severidade"),
    ("cvss_referencia_fonte", "fonte"),
    ("cvss_referencia_tipo", "tipo"),
]

for campo_cves, campo_cvss in campos:

    iguais = (
        comparacao[campo_cves].eq(
            comparacao[campo_cvss]
        )
        | (
            comparacao[campo_cves].isna()
            & comparacao[campo_cvss].isna()
        )
    )

    assert iguais.all(), (
        f"Divergência encontrada: {campo_cves}"
    )


# ==========================================
# 7. RELATÓRIO
# ==========================================

print("\nVALIDAÇÃO SILVER — CVSS")

print("Avaliações:", len(df_cvss))

print(
    "CVEs com avaliações:",
    df_cvss["cve_id"].nunique()
)

print(
    "Avaliações de referência:",
    len(df_referencia)
)

print(
    "Referências duplicadas:",
    int(
        df_referencia["cve_id"]
        .duplicated()
        .sum()
    )
)

print("\nAVALIAÇÕES POR VERSÃO")

print(
    df_cvss["versao_cvss"]
    .value_counts()
    .sort_index()
    .to_string()
)

print("\nValidação Silver CVSS: OK")
