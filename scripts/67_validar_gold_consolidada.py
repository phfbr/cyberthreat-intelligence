
from pathlib import Path

import pandas as pd


# ==========================================
# 1. LOCALIZAR AS TABELAS GOLD
# ==========================================

pasta = Path("data/gold/nvd")

nomes = [
    "fato_vulnerabilidade",
    "dim_status",
    "dim_data",
    "dim_cwe",
    "ponte_cve_cwe",
    "dim_produto",
    "ponte_cve_produto",
    "fato_avaliacao_cvss",
]

tabelas = {}

for nome in nomes:
    arquivo = pasta / f"{nome}.parquet"

    if not arquivo.exists():
        raise FileNotFoundError(
            f"Arquivo não encontrado: {arquivo}"
        )

    tabelas[nome] = pd.read_parquet(arquivo)


# ==========================================
# 2. SEPARAR AS TABELAS
# ==========================================

fato = tabelas["fato_vulnerabilidade"]
status = tabelas["dim_status"]
datas = tabelas["dim_data"]
cwe = tabelas["dim_cwe"]
ponte_cwe = tabelas["ponte_cve_cwe"]
produto = tabelas["dim_produto"]
ponte_produto = tabelas["ponte_cve_produto"]
cvss = tabelas["fato_avaliacao_cvss"]


# ==========================================
# 3. VALIDAR GRANULARIDADE
# ==========================================

assert len(fato) == 2743
assert fato["cve_id"].is_unique

assert len(status) == 7
assert status["status_id"].is_unique

assert len(datas) == 29
assert datas["data_id"].is_unique

assert len(cwe) == 251
assert cwe["cwe_id"].is_unique

assert len(produto) == 1009
assert produto["produto_id"].is_unique

assert len(ponte_cwe) == 2968
assert not ponte_cwe.duplicated(
    ["cve_id", "cwe_id"]
).any()

assert not ponte_produto.duplicated(
    ["cve_id", "produto_id"]
).any()

assert len(cvss) == 3372
assert cvss["avaliacao_cvss_id"].is_unique


# ==========================================
# 4. VALIDAR RELACIONAMENTOS
# ==========================================

relacionamentos = [
    (
        "Fato -> Status",
        fato["status_id"],
        status["status_id"],
    ),
    (
        "Fato -> Data publicação",
        fato["data_publicacao_id"],
        datas["data_id"],
    ),
    (
        "Fato -> Data atualização",
        fato["data_atualizacao_id"],
        datas["data_id"],
    ),
    (
        "Ponte CWE -> Fato",
        ponte_cwe["cve_id"],
        fato["cve_id"],
    ),
    (
        "Ponte CWE -> Dim CWE",
        ponte_cwe["cwe_id"],
        cwe["cwe_id"],
    ),
    (
        "Ponte Produto -> Fato",
        ponte_produto["cve_id"],
        fato["cve_id"],
    ),
    (
        "Ponte Produto -> Dim Produto",
        ponte_produto["produto_id"],
        produto["produto_id"],
    ),
    (
        "Fato CVSS -> Fato CVE",
        cvss["cve_id"],
        fato["cve_id"],
    ),
]

for nome, origem, destino in relacionamentos:
    invalidos = int(
        (~origem.isin(destino)).sum()
    )

    assert origem.notna().all(), (
        f"Chaves nulas: {nome}"
    )

    assert invalidos == 0, (
        f"Relacionamento inválido: {nome}"
    )

    print(f"[OK] {nome}")


# ==========================================
# 5. VALIDAR INDICADORES PRINCIPAIS
# ==========================================

assert int(fato["flag_possui_cvss"].sum()) == 2569
assert int(fato["flag_possui_cwe"].sum()) == 2516
assert int(fato["flag_possui_cpe"].sum()) == 715
assert int(fato["flag_rejeitada"].sum()) == 17

assert ponte_cwe["cve_id"].nunique() == 2516
assert ponte_produto["cve_id"].nunique() == 715

referencias = cvss.loc[
    cvss["flag_cvss_referencia"].astype(bool)
]

assert len(referencias) == 2569
assert referencias["cve_id"].is_unique


# ==========================================
# 6. VALIDAR CONSISTÊNCIA ENTRE TABELAS
# ==========================================

assert set(
    fato.loc[
        fato["flag_possui_cwe"].astype(bool),
        "cve_id",
    ]
) == set(ponte_cwe["cve_id"])

assert set(
    fato.loc[
        fato["flag_possui_cpe"].astype(bool),
        "cve_id",
    ]
) == set(ponte_produto["cve_id"])

assert set(
    fato.loc[
        fato["flag_possui_cvss"].astype(bool),
        "cve_id",
    ]
) == set(referencias["cve_id"])


# ==========================================
# 7. RELATÓRIO CONSOLIDADO
# ==========================================

print("\nAUDITORIA CONSOLIDADA — GOLD")

print("\nTABELAS")

for nome, df in tabelas.items():
    print(
        f"{nome}: "
        f"{len(df)} linhas | "
        f"{len(df.columns)} colunas"
    )

print("\nINDICADORES")

print("CVEs únicas:", len(fato))
print("CVEs com CVSS:", int(fato["flag_possui_cvss"].sum()))
print("CVEs com CWE:", int(fato["flag_possui_cwe"].sum()))
print("CVEs com CPE:", int(fato["flag_possui_cpe"].sum()))
print("CVEs rejeitadas:", int(fato["flag_rejeitada"].sum()))

print("\nRelacionamentos inválidos: 0")

print("\nAuditoria Consolidada Gold: OK")
