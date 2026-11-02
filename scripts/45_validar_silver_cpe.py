
from pathlib import Path

import pandas as pd


# ==========================================
# 1. LOCALIZAR OS ARQUIVOS
# ==========================================

pasta = Path("data/silver/nvd")

arquivo_cpe = pasta / "silver_cpe.parquet"
arquivo_cves = pasta / "silver_cves.parquet"

for arquivo in [arquivo_cpe, arquivo_cves]:
    if not arquivo.exists():
        raise FileNotFoundError(
            f"Arquivo não encontrado: {arquivo}"
        )


# ==========================================
# 2. LER OS ARQUIVOS
# ==========================================

df_cpe = pd.read_parquet(arquivo_cpe)

df_cves = pd.read_parquet(
    arquivo_cves,
    columns=["cve_id"]
)


# ==========================================
# 3. VALIDAR ESTRUTURA
# ==========================================

colunas_esperadas = [
    "cve_id",
    "cpe_criteria",
    "tipo_plataforma",
    "fabricante",
    "produto",
    "vulnerable",
    "match_criteria_id",
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
    "caminho_configuracao",
    "indice_match",
    "operador_no",
    "negacao_no",
]

assert list(df_cpe.columns) == colunas_esperadas

assert len(df_cpe) == 8180

assert df_cpe["cve_id"].notna().all()

assert df_cpe["cpe_criteria"].notna().all()

assert df_cpe["caminho_configuracao"].notna().all()

assert df_cpe["indice_match"].notna().all()


# ==========================================
# 4. VALIDAR IDENTIDADE DAS OCORRÊNCIAS
# ==========================================

chave_ocorrencia = [
    "cve_id",
    "caminho_configuracao",
    "indice_match",
]

duplicadas = df_cpe.duplicated(
    subset=chave_ocorrencia
)

assert not duplicadas.any(), (
    "Existem ocorrências CPE duplicadas."
)


# ==========================================
# 5. VALIDAR RELACIONAMENTOS
# ==========================================

assert df_cves["cve_id"].is_unique

cves_inexistentes = ~df_cpe["cve_id"].isin(
    df_cves["cve_id"]
)

assert not cves_inexistentes.any(), (
    "Existem CVEs inexistentes na tabela CPE."
)


# ==========================================
# 6. VALIDAR INDICADORES
# ==========================================

assert len(df_cves) == 2743

assert df_cpe["cve_id"].nunique() == 715

assert df_cpe["fabricante"].nunique() == 45

pares_distintos = df_cpe[
    ["fabricante", "produto"]
].drop_duplicates().shape[0]

assert pares_distintos == 1009

tipos = df_cpe[
    "tipo_plataforma"
].value_counts()

assert tipos.get("o", 0) == 3342
assert tipos.get("h", 0) == 3059
assert tipos.get("a", 0) == 1779

assert df_cpe["tipo_plataforma"].isin(
    ["o", "h", "a"]
).all()

# Verificar valores do indicador vulnerable
assert df_cpe["vulnerable"].isin(
    [True, False]
).all()


# ==========================================
# 7. RELATÓRIO
# ==========================================

print("\nVALIDAÇÃO SILVER — CPE")

print("CVEs analisadas:", len(df_cves))
print("Registros CPE:", len(df_cpe))
print("CVEs com CPE:", df_cpe["cve_id"].nunique())
print("Fabricantes distintos:", df_cpe["fabricante"].nunique())
print("Pares fabricante/produto:", pares_distintos)

print(
    "Ocorrências duplicadas:",
    int(duplicadas.sum())
)

print(
    "CVEs inexistentes:",
    int(cves_inexistentes.sum())
)

print("\nINDICADOR VULNERABLE")

print(
    df_cpe["vulnerable"]
    .value_counts(dropna=False)
    .to_string()
)

print("\nValidação Silver CPE: OK")
