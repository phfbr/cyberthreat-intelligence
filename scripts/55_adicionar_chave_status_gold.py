
from pathlib import Path

import pandas as pd


# ==========================================
# 1. DEFINIR CAMINHOS
# ==========================================

pasta_gold = Path("data/gold/nvd")

arquivo_fato = pasta_gold / "fato_vulnerabilidade.parquet"
arquivo_status = pasta_gold / "dim_status.parquet"

arquivo_temporario = (
    pasta_gold / "fato_vulnerabilidade_status_temp.parquet"
)


# ==========================================
# 2. CARREGAR OS DADOS
# ==========================================

df_fato = pd.read_parquet(arquivo_fato)
df_status = pd.read_parquet(arquivo_status)


# ==========================================
# 3. VALIDAR ESTRUTURA ORIGINAL
# ==========================================

assert len(df_fato) == 2743
assert len(df_fato.columns) == 13
assert df_fato["cve_id"].is_unique

assert len(df_status) == 7
assert df_status["status_id"].is_unique
assert df_status["status_nvd"].is_unique

if "status_id" in df_fato.columns:
    raise ValueError(
        "A coluna status_id já existe na tabela fato."
    )


# ==========================================
# 4. ADICIONAR CHAVE DE STATUS
# ==========================================

df_resultado = df_fato.merge(
    df_status[["status_id", "status_nvd"]],
    on="status_nvd",
    how="left",
    validate="many_to_one",
    indicator=True,
)


# ==========================================
# 5. VALIDAR O RELACIONAMENTO
# ==========================================

sem_correspondencia = int(
    (df_resultado["_merge"] != "both").sum()
)

assert sem_correspondencia == 0
assert df_resultado["status_id"].notna().all()

assert len(df_resultado) == 2743
assert df_resultado["cve_id"].is_unique

df_resultado = df_resultado.drop(
    columns=["_merge"]
)

df_resultado["status_id"] = (
    df_resultado["status_id"].astype(int)
)

assert len(df_resultado.columns) == 14

# Preservar os indicadores já validados.
assert int(df_resultado["flag_possui_cvss"].sum()) == 2569
assert int(df_resultado["flag_possui_cwe"].sum()) == 2516
assert int(df_resultado["flag_possui_cpe"].sum()) == 715
assert int(df_resultado["flag_rejeitada"].sum()) == 17


# ==========================================
# 6. SALVAR E VERIFICAR
# ==========================================

df_resultado.to_parquet(
    arquivo_temporario,
    index=False,
)

df_teste = pd.read_parquet(arquivo_temporario)

assert len(df_teste) == 2743
assert len(df_teste.columns) == 14
assert df_teste["cve_id"].is_unique
assert df_teste["status_id"].notna().all()

arquivo_temporario.replace(arquivo_fato)


# ==========================================
# 7. RELATÓRIO
# ==========================================

print("\nATUALIZAÇÃO GOLD — CHAVE DE STATUS")

print("CVEs:", len(df_resultado))
print("Colunas:", len(df_resultado.columns))
print("Status sem correspondência:", sem_correspondencia)

print("\nDISTRIBUIÇÃO POR STATUS")

distribuicao = (
    df_resultado.groupby(
        ["status_id", "status_nvd"]
    )
    .size()
    .reset_index(name="quantidade_cves")
    .sort_values("status_id")
)

print(distribuicao.to_string(index=False))

print("\nArquivo atualizado:", arquivo_fato)
print("\nChave de Status Gold: OK")
