
from pathlib import Path

import pandas as pd


# ==========================================
# 1. LOCALIZAR ARQUIVOS
# ==========================================

pasta = Path("data/silver/nvd")

arquivos = {
    "cves": pasta / "silver_cves.parquet",
    "cwe": pasta / "silver_cwe.parquet",
    "cvss": pasta / "silver_cvss.parquet",
    "cpe": pasta / "silver_cpe.parquet",
}

for nome, caminho in arquivos.items():
    if not caminho.exists():
        raise FileNotFoundError(
            f"Arquivo ausente: {nome} - {caminho}"
        )


# ==========================================
# 2. CARREGAR TABELAS
# ==========================================

tabelas = {
    nome: pd.read_parquet(caminho)
    for nome, caminho in arquivos.items()
}

cves = tabelas["cves"]
cwe = tabelas["cwe"]
cvss = tabelas["cvss"]
cpe = tabelas["cpe"]


# ==========================================
# 3. VALIDAR QUANTIDADES
# ==========================================

esperados = {
    "cves": 2743,
    "cwe": 2968,
    "cvss": 3372,
    "cpe": 8180,
}

for nome, quantidade in esperados.items():
    assert len(tabelas[nome]) == quantidade, (
        f"Quantidade inesperada: {nome}"
    )


# ==========================================
# 4. VALIDAR CHAVES
# ==========================================

assert cves["cve_id"].notna().all()
assert cves["cve_id"].is_unique

assert not cwe.duplicated(
    ["cve_id", "cwe_id"]
).any()

assert not cvss.duplicated(
    ["cve_id", "chave_metrica", "indice_origem"]
).any()

assert not cpe.duplicated(
    ["cve_id", "caminho_configuracao", "indice_match"]
).any()


# ==========================================
# 5. VALIDAR RELACIONAMENTOS
# ==========================================

ids_cves = set(cves["cve_id"])

for nome in ["cwe", "cvss", "cpe"]:

    ids_relacionados = set(
        tabelas[nome]["cve_id"]
    )

    ids_inexistentes = (
        ids_relacionados - ids_cves
    )

    assert not ids_inexistentes, (
        f"CVEs inexistentes na tabela {nome}"
    )


# ==========================================
# 6. VALIDAR COBERTURA
# ==========================================

assert cwe["cve_id"].nunique() == 2516
assert cvss["cve_id"].nunique() == 2569
assert cpe["cve_id"].nunique() == 715

assert int(cves["flag_rejeitada"].sum()) == 17

assert int(
    cvss["flag_cvss_referencia"].sum()
) == 2569

assert cvss.loc[
    cvss["flag_cvss_referencia"],
    "cve_id"
].is_unique


# ==========================================
# 7. RELATÓRIO
# ==========================================

print("\nVALIDAÇÃO CONSOLIDADA — SILVER")

for nome, df in tabelas.items():

    print(
        f"{nome.upper()}: "
        f"{len(df)} linhas | "
        f"{len(df.columns)} colunas"
    )

print("\nCOBERTURA")

print(
    "CVEs com CWE:",
    cwe["cve_id"].nunique()
)

print(
    "CVEs com CVSS:",
    cvss["cve_id"].nunique()
)

print(
    "CVEs com CPE:",
    cpe["cve_id"].nunique()
)

print("\nINTEGRIDADE")

print("Chaves principais: OK")
print("Relacionamentos: OK")
print("Quantidades: OK")
print("Cobertura: OK")

print("\nValidação consolidada Silver: OK")
