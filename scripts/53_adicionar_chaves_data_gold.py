
from pathlib import Path

import pandas as pd


# ==========================================
# 1. DEFINIR CAMINHOS
# ==========================================

pasta_gold = Path("data/gold/nvd")

arquivo_fato = (
    pasta_gold / "fato_vulnerabilidade.parquet"
)

arquivo_data = (
    pasta_gold / "dim_data.parquet"
)


# ==========================================
# 2. CARREGAR AS TABELAS
# ==========================================

df_fato = pd.read_parquet(arquivo_fato)

df_data = pd.read_parquet(
    arquivo_data,
    columns=["data_id"]
)


# ==========================================
# 3. VERIFICAR ESTRUTURA ORIGINAL
# ==========================================

assert len(df_fato) == 2743
assert df_fato["cve_id"].is_unique

assert df_data["data_id"].is_unique

# Não modificar o arquivo caso as chaves
# já tenham sido adicionadas.
novas_colunas = [
    "data_publicacao_id",
    "data_atualizacao_id",
]

for coluna in novas_colunas:
    if coluna in df_fato.columns:
        raise ValueError(
            f"A coluna já existe: {coluna}"
        )


# ==========================================
# 4. CRIAR CHAVES DE DATA
# ==========================================

df_fato["data_publicacao_id"] = (
    df_fato["data_publicacao"]
    .dt.strftime("%Y%m%d")
    .astype(int)
)

df_fato["data_atualizacao_id"] = (
    df_fato["data_atualizacao"]
    .dt.strftime("%Y%m%d")
    .astype(int)
)


# ==========================================
# 5. VALIDAR RELACIONAMENTOS
# ==========================================

ids_calendario = set(df_data["data_id"])

assert df_fato["data_publicacao_id"].isin(
    ids_calendario
).all()

assert df_fato["data_atualizacao_id"].isin(
    ids_calendario
).all()

assert df_fato[
    ["data_publicacao_id", "data_atualizacao_id"]
].notna().all().all()

assert len(df_fato) == 2743
assert df_fato["cve_id"].is_unique
assert len(df_fato.columns) == 13


# ==========================================
# 6. SALVAR COM SEGURANÇA
# ==========================================

# Salvar primeiro em um arquivo temporário.
arquivo_temporario = (
    pasta_gold / "fato_vulnerabilidade_temp.parquet"
)

df_fato.to_parquet(
    arquivo_temporario,
    index=False
)

# Conferir se o arquivo temporário
# pode ser lido corretamente.
df_teste = pd.read_parquet(
    arquivo_temporario
)

assert len(df_teste) == 2743
assert len(df_teste.columns) == 13
assert df_teste["cve_id"].is_unique

# Substituir o arquivo original somente
# depois das verificações.
arquivo_temporario.replace(arquivo_fato)


# ==========================================
# 7. RELATÓRIO
# ==========================================

print("\nATUALIZAÇÃO GOLD — CHAVES DE DATA")

print("Registros:", len(df_fato))
print("Colunas:", len(df_fato.columns))

print(
    "Publicações com chave:",
    df_fato["data_publicacao_id"].notna().sum()
)

print(
    "Atualizações com chave:",
    df_fato["data_atualizacao_id"].notna().sum()
)

print("\nEXEMPLO")

print(
    df_fato[
        [
            "cve_id",
            "data_publicacao_id",
            "data_atualizacao_id",
        ]
    ].head().to_string(index=False)
)

print("\nArquivo atualizado:", arquivo_fato)

print("\nChaves de Data Gold: OK")
