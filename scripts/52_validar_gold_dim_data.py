
from pathlib import Path

import pandas as pd


# ==========================================
# 1. LOCALIZAR OS ARQUIVOS
# ==========================================

pasta_gold = Path("data/gold/nvd")

arquivo_data = pasta_gold / "dim_data.parquet"
arquivo_fato = pasta_gold / "fato_vulnerabilidade.parquet"

for arquivo in [arquivo_data, arquivo_fato]:
    if not arquivo.exists():
        raise FileNotFoundError(
            f"Arquivo não encontrado: {arquivo}"
        )


# ==========================================
# 2. CARREGAR AS TABELAS
# ==========================================

df_data = pd.read_parquet(arquivo_data)

df_fato = pd.read_parquet(
    arquivo_fato,
    columns=[
        "cve_id",
        "data_publicacao",
        "data_atualizacao",
    ],
)


# ==========================================
# 3. VALIDAR ESTRUTURA
# ==========================================

colunas_esperadas = [
    "data_id",
    "data",
    "ano",
    "mes_numero",
    "dia",
    "trimestre",
    "ano_mes",
    "dia_semana_numero",
]

assert list(df_data.columns) == colunas_esperadas

assert len(df_data) == 29

assert df_data["data_id"].is_unique
assert df_data["data"].is_unique

assert df_data.notna().all().all()

assert df_data["data"].dt.tz is not None


# ==========================================
# 4. VALIDAR CONTINUIDADE DO CALENDÁRIO
# ==========================================

datas_esperadas = pd.date_range(
    start="2026-10-01",
    end="2026-10-29",
    freq="D",
    tz="UTC",
)

datas_reais = pd.DatetimeIndex(
    df_data["data"].sort_values()
)

assert datas_reais.equals(datas_esperadas)

assert (
    df_data["data_id"]
    == df_data["data"].dt.strftime("%Y%m%d").astype(int)
).all()


# ==========================================
# 5. VALIDAR ATRIBUTOS DE DATA
# ==========================================

assert (
    df_data["ano"]
    == df_data["data"].dt.year
).all()

assert (
    df_data["mes_numero"]
    == df_data["data"].dt.month
).all()

assert (
    df_data["dia"]
    == df_data["data"].dt.day
).all()

assert (
    df_data["trimestre"]
    == df_data["data"].dt.quarter
).all()

assert (
    df_data["ano_mes"]
    == df_data["data"].dt.strftime("%Y-%m")
).all()

assert (
    df_data["dia_semana_numero"]
    == df_data["data"].dt.day_of_week + 1
).all()


# ==========================================
# 6. VALIDAR COBERTURA DA TABELA FATO
# ==========================================

datas_calendario = set(df_data["data_id"])

publicacao_ids = (
    df_fato["data_publicacao"]
    .dt.strftime("%Y%m%d")
    .astype(int)
)

atualizacao_ids = (
    df_fato["data_atualizacao"]
    .dt.strftime("%Y%m%d")
    .astype(int)
)

publicacoes_fora = int(
    (~publicacao_ids.isin(datas_calendario)).sum()
)

atualizacoes_fora = int(
    (~atualizacao_ids.isin(datas_calendario)).sum()
)

assert publicacoes_fora == 0
assert atualizacoes_fora == 0


# ==========================================
# 7. RELATÓRIO
# ==========================================

print("\nVALIDAÇÃO GOLD — DIM DATA")

print("Datas no calendário:", len(df_data))

print(
    "Primeira data:",
    df_data["data"].min()
)

print(
    "Última data:",
    df_data["data"].max()
)

print("Datas duplicadas:", int(
    df_data["data"].duplicated().sum()
))

print(
    "Publicações fora do calendário:",
    publicacoes_fora
)

print(
    "Atualizações fora do calendário:",
    atualizacoes_fora
)

print("\nValidação Gold Dim Data: OK")
