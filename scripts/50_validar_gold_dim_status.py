
from pathlib import Path

import pandas as pd


# ==========================================
# 1. LOCALIZAR OS ARQUIVOS
# ==========================================

pasta_gold = Path("data/gold/nvd")

arquivo_status = pasta_gold / "dim_status.parquet"
arquivo_fato = pasta_gold / "fato_vulnerabilidade.parquet"

for arquivo in [arquivo_status, arquivo_fato]:
    if not arquivo.exists():
        raise FileNotFoundError(
            f"Arquivo não encontrado: {arquivo}"
        )


# ==========================================
# 2. CARREGAR AS TABELAS
# ==========================================

df_status = pd.read_parquet(arquivo_status)

df_fato = pd.read_parquet(
    arquivo_fato,
    columns=["cve_id", "status_nvd"]
)


# ==========================================
# 3. VALIDAR ESTRUTURA
# ==========================================

assert list(df_status.columns) == [
    "status_id",
    "status_nvd",
]

assert len(df_status) == 7

assert df_status["status_id"].is_unique
assert df_status["status_nvd"].is_unique

assert df_status.notna().all().all()

assert set(df_status["status_id"]) == set(range(1, 8))


# ==========================================
# 4. VALIDAR RELACIONAMENTO
# ==========================================

comparacao = df_fato.merge(
    df_status,
    on="status_nvd",
    how="left",
    validate="many_to_one",
    indicator=True,
)

sem_correspondencia = (
    comparacao["_merge"] != "both"
).sum()

assert len(comparacao) == 2743
assert sem_correspondencia == 0
assert comparacao["status_id"].notna().all()


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
# 6. RELATÓRIO
# ==========================================

print("\nVALIDAÇÃO GOLD — DIM STATUS")

print("Status distintos:", len(df_status))
print("CVEs analisadas:", len(df_fato))
print("Status duplicados:", int(
    df_status["status_nvd"].duplicated().sum()
))
print("CVEs sem correspondência:", int(
    sem_correspondencia
))

print("\nDISTRIBUIÇÃO POR STATUS")

print(
    df_fato["status_nvd"]
    .value_counts()
    .to_string()
)

print("\nValidação Gold Dim Status: OK")
