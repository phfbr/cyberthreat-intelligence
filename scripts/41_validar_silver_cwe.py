
from pathlib import Path

import pandas as pd


# ==========================================
# 1. LOCALIZAR ARQUIVOS
# ==========================================

pasta = Path("data/silver/nvd")

arquivo_cwe = pasta / "silver_cwe.parquet"
arquivo_cves = pasta / "silver_cves.parquet"

for arquivo in [arquivo_cwe, arquivo_cves]:
    if not arquivo.exists():
        raise FileNotFoundError(
            f"Arquivo não encontrado: {arquivo}"
        )


# ==========================================
# 2. LER OS ARQUIVOS
# ==========================================

df_cwe = pd.read_parquet(arquivo_cwe)

df_cves = pd.read_parquet(
    arquivo_cves,
    columns=["cve_id"]
)


# ==========================================
# 3. VALIDAR ESTRUTURA
# ==========================================

assert list(df_cwe.columns) == [
    "cve_id",
    "cwe_id"
]

assert len(df_cwe) == 2968

assert df_cwe.notna().all().all()

assert not df_cwe.duplicated(
    subset=["cve_id", "cwe_id"]
).any()

assert df_cwe["cwe_id"].str.fullmatch(
    r"CWE-\d+"
).all()


# ==========================================
# 4. VALIDAR RELACIONAMENTOS
# ==========================================

assert df_cves["cve_id"].is_unique

cves_inexistentes = ~df_cwe["cve_id"].isin(
    df_cves["cve_id"]
)

assert not cves_inexistentes.any(), (
    "Existem associações com CVEs inexistentes."
)


# ==========================================
# 5. VALIDAR INDICADORES
# ==========================================

total_cves = len(df_cves)

cves_com_cwe = df_cwe["cve_id"].nunique()

cves_sem_cwe = total_cves - cves_com_cwe

cves_multiplas = int(
    (
        df_cwe.groupby("cve_id")
        .size() > 1
    ).sum()
)

codigos_distintos = df_cwe["cwe_id"].nunique()

assert total_cves == 2743
assert cves_com_cwe == 2516
assert cves_sem_cwe == 227
assert cves_multiplas == 394
assert codigos_distintos == 251


# ==========================================
# 6. RELATÓRIO
# ==========================================

print("\nVALIDAÇÃO SILVER — CWE")

print("CVEs na tabela principal:", total_cves)
print("Associações CVE-CWE:", len(df_cwe))
print("CVEs com CWE:", cves_com_cwe)
print("CVEs sem CWE:", cves_sem_cwe)
print("CVEs com múltiplas CWE:", cves_multiplas)
print("Códigos CWE distintos:", codigos_distintos)

print(
    "Associações duplicadas:",
    int(
        df_cwe.duplicated(
            subset=["cve_id", "cwe_id"]
        ).sum()
    )
)

print(
    "CVEs inexistentes:",
    int(cves_inexistentes.sum())
)

print("\nTIPOS DE DADOS")

print(df_cwe.dtypes.to_string())

print("\nValidação Silver CWE: OK")
