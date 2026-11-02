
from pathlib import Path

import pandas as pd


# ==========================================
# 1. DEFINIR CAMINHOS
# ==========================================

pasta_silver = Path("data/silver/nvd")
pasta_gold = Path("data/gold/nvd")

pasta_gold.mkdir(
    parents=True,
    exist_ok=True
)


# ==========================================
# 2. CARREGAR AS TABELAS SILVER
# ==========================================

df_cves = pd.read_parquet(
    pasta_silver / "silver_cves.parquet"
)

df_cwe = pd.read_parquet(
    pasta_silver / "silver_cwe.parquet"
)

df_cpe = pd.read_parquet(
    pasta_silver / "silver_cpe.parquet"
)

df_cvss = pd.read_parquet(
    pasta_silver / "silver_cvss.parquet"
)


# ==========================================
# 3. CONFERIR COLUNAS DA SILVER
# ==========================================

print("\nCOLUNAS DISPONÍVEIS — SILVER_CVES")

for coluna in df_cves.columns:
    print("-", coluna)


# ==========================================
# 4. IDENTIFICAR COLUNAS
# ==========================================

def localizar_coluna(candidatas):

    encontradas = [
        coluna
        for coluna in candidatas
        if coluna in df_cves.columns
    ]

    if len(encontradas) != 1:
        raise ValueError(
            "Não foi possível identificar uma "
            f"coluna única entre: {candidatas}. "
            f"Encontradas: {encontradas}"
        )

    return encontradas[0]


mapeamento = {
    "cve_id": localizar_coluna(
        ["cve_id"]
    ),
    "data_publicacao": localizar_coluna(
        ["data_publicacao", "published"]
    ),
    "data_atualizacao": localizar_coluna(
    ["data_modificacao"]
    ),
    "status_nvd": localizar_coluna(
        ["status_nvd", "vuln_status"]
    ),
    "flag_rejeitada": localizar_coluna(
        ["flag_rejeitada"]
    ),
    "cvss_versao": localizar_coluna(
        ["cvss_referencia_versao"]
    ),
    "cvss_pontuacao": localizar_coluna(
        ["cvss_referencia_pontuacao"]
    ),
    "cvss_severidade": localizar_coluna(
        ["cvss_referencia_severidade"]
    ),
}


# ==========================================
# 5. CONSTRUIR A TABELA GOLD
# ==========================================

df_gold = df_cves[
    list(mapeamento.values())
].copy()

df_gold.columns = list(
    mapeamento.keys()
)


# ==========================================
# 6. CRIAR INDICADORES DE COBERTURA
# ==========================================

df_gold["flag_possui_cvss"] = (
    df_gold["cve_id"].isin(
        df_cvss["cve_id"]
    )
)

df_gold["flag_possui_cwe"] = (
    df_gold["cve_id"].isin(
        df_cwe["cve_id"]
    )
)

df_gold["flag_possui_cpe"] = (
    df_gold["cve_id"].isin(
        df_cpe["cve_id"]
    )
)


# ==========================================
# 7. VALIDAR RESULTADOS
# ==========================================

assert len(df_gold) == 2743

assert df_gold["cve_id"].is_unique

assert df_gold["cve_id"].notna().all()

assert int(
    df_gold["flag_possui_cvss"].sum()
) == 2569

assert int(
    df_gold["flag_possui_cwe"].sum()
) == 2516

assert int(
    df_gold["flag_possui_cpe"].sum()
) == 715

assert int(
    df_gold["flag_rejeitada"].sum()
) == 17

assert int(
    df_gold["cvss_pontuacao"].notna().sum()
) == 2569

assert df_gold[
    "cvss_pontuacao"
].dropna().between(0, 10).all()


# ==========================================
# 8. ORDENAR E SALVAR
# ==========================================

df_gold = df_gold.sort_values(
    "cve_id"
).reset_index(drop=True)

arquivo_saida = (
    pasta_gold / "fato_vulnerabilidade.parquet"
)

df_gold.to_parquet(
    arquivo_saida,
    index=False
)


# ==========================================
# 9. EXIBIR RELATÓRIO
# ==========================================

print("\nCONSTRUÇÃO GOLD — FATO VULNERABILIDADE")

print("Registros:", len(df_gold))

print("Colunas:", len(df_gold.columns))

print(
    "CVEs únicas:",
    df_gold["cve_id"].nunique()
)

print(
    "CVEs com CVSS:",
    int(df_gold["flag_possui_cvss"].sum())
)

print(
    "CVEs com CWE:",
    int(df_gold["flag_possui_cwe"].sum())
)

print(
    "CVEs com CPE:",
    int(df_gold["flag_possui_cpe"].sum())
)

print(
    "CVEs rejeitadas:",
    int(df_gold["flag_rejeitada"].sum())
)

print("\nTIPOS DE DADOS")

print(df_gold.dtypes.to_string())

print("\nArquivo gerado:", arquivo_saida)

print("\nGold Fato Vulnerabilidade: OK")
