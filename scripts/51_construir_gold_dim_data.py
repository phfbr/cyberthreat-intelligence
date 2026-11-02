
from pathlib import Path

import pandas as pd


# ==========================================
# 1. DEFINIR CAMINHOS
# ==========================================

pasta_gold = Path("data/gold/nvd")

arquivo_fato = (
    pasta_gold / "fato_vulnerabilidade.parquet"
)

arquivo_saida = (
    pasta_gold / "dim_data.parquet"
)


# ==========================================
# 2. CARREGAR AS DATAS DA FATO
# ==========================================

df_fato = pd.read_parquet(
    arquivo_fato,
    columns=[
        "data_publicacao",
        "data_atualizacao",
    ]
)


# ==========================================
# 3. IDENTIFICAR O PERÍODO
# ==========================================

data_inicial = min(
    df_fato["data_publicacao"].min(),
    df_fato["data_atualizacao"].min(),
).normalize()

data_final = max(
    df_fato["data_publicacao"].max(),
    df_fato["data_atualizacao"].max(),
).normalize()

print("\nPERÍODO IDENTIFICADO")
print("Data inicial:", data_inicial)
print("Data final:", data_final)


# ==========================================
# 4. CONSTRUIR O CALENDÁRIO
# ==========================================

datas = pd.date_range(
    start=data_inicial,
    end=data_final,
    freq="D",
    tz="UTC",
)

df_data = pd.DataFrame({
    "data": datas,
})

df_data["data_id"] = (
    df_data["data"].dt.strftime("%Y%m%d").astype(int)
)

df_data["ano"] = df_data["data"].dt.year

df_data["mes_numero"] = df_data["data"].dt.month

df_data["dia"] = df_data["data"].dt.day

df_data["trimestre"] = (
    df_data["data"].dt.quarter
)

df_data["ano_mes"] = (
    df_data["data"].dt.strftime("%Y-%m")
)

df_data["dia_semana_numero"] = (
    df_data["data"].dt.day_of_week + 1
)

df_data = df_data[
    [
        "data_id",
        "data",
        "ano",
        "mes_numero",
        "dia",
        "trimestre",
        "ano_mes",
        "dia_semana_numero",
    ]
]


# ==========================================
# 5. VALIDAÇÕES INICIAIS
# ==========================================

assert not df_data.empty

assert df_data["data_id"].is_unique

assert df_data["data"].is_unique

assert df_data.notna().all().all()

assert df_data["data"].min() == data_inicial

assert df_data["data"].max() == data_final

assert df_data["dia_semana_numero"].between(
    1, 7
).all()


# ==========================================
# 6. SALVAR
# ==========================================

df_data.to_parquet(
    arquivo_saida,
    index=False,
)


# ==========================================
# 7. RELATÓRIO
# ==========================================

print("\nCONSTRUÇÃO GOLD — DIM DATA")

print("Registros:", len(df_data))
print("Colunas:", len(df_data.columns))

print(
    "Primeira data:",
    df_data["data"].min()
)

print(
    "Última data:",
    df_data["data"].max()
)

print("\nPRIMEIRAS LINHAS")

print(
    df_data.head().to_string(index=False)
)

print("\nArquivo gerado:", arquivo_saida)

print("\nGold Dim Data: OK")
