
from pathlib import Path

import pandas as pd


# ==========================================
# 1. LOCALIZAR OS ARQUIVOS
# ==========================================

pasta_gold = Path("data/gold/nvd")

arquivo_fato = (
    pasta_gold / "fato_vulnerabilidade.parquet"
)

arquivo_status = (
    pasta_gold / "dim_status.parquet"
)


# ==========================================
# 2. CARREGAR OS DADOS
# ==========================================

df_fato = pd.read_parquet(arquivo_fato)
df_status = pd.read_parquet(arquivo_status)


# ==========================================
# 3. VALIDAR ESTRUTURA
# ==========================================

assert len(df_fato) == 2743
assert len(df_fato.columns) == 14

assert df_fato["cve_id"].is_unique
assert df_fato["cve_id"].notna().all()

assert len(df_status) == 7
assert df_status["status_id"].is_unique
assert df_status["status_nvd"].is_unique

assert df_fato["status_id"].notna().all()


# ==========================================
# 4. VALIDAR CHAVES E STATUS
# ==========================================

comparacao = df_fato[
    ["cve_id", "status_id", "status_nvd"]
].merge(
    df_status,
    on="status_id",
    how="left",
    validate="many_to_one",
    indicator=True,
    suffixes=("_fato", "_dim"),
)

sem_correspondencia = int(
    (comparacao["_merge"] != "both").sum()
)

status_divergentes = int(
    (
        comparacao["status_nvd_fato"]
        != comparacao["status_nvd_dim"]
    ).sum()
)

assert sem_correspondencia == 0
assert status_divergentes == 0

assert len(comparacao) == 2743


# ==========================================
# 5. VALIDAR DISTRIBUIÇÃO
# ==========================================

distribuicao_esperada = {
    "Deferred": 1342,
    "Analyzed": 689,
    "Awaiting Analysis": 442,
    "Received": 209,
    "Modified": 26,
    "Undergoing Analysis": 18,
    "Rejected": 17,
}

distribuicao_real = (
    df_fato["status_nvd"]
    .value_counts()
    .to_dict()
)

assert distribuicao_real == distribuicao_esperada


# ==========================================
# 6. VALIDAR INDICADORES
# ==========================================

assert int(df_fato["flag_possui_cvss"].sum()) == 2569
assert int(df_fato["flag_possui_cwe"].sum()) == 2516
assert int(df_fato["flag_possui_cpe"].sum()) == 715
assert int(df_fato["flag_rejeitada"].sum()) == 17


# ==========================================
# 7. RELATÓRIO
# ==========================================

print("\nVALIDAÇÃO GOLD — CHAVE DE STATUS")

print("CVEs:", len(df_fato))
print("Colunas:", len(df_fato.columns))
print("Status distintos:", len(df_status))

print(
    "Chaves sem correspondência:",
    sem_correspondencia
)

print(
    "Status divergentes:",
    status_divergentes
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

print("\nValidação Chave de Status Gold: OK")
