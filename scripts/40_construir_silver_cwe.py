
import json
import re
from pathlib import Path

import pandas as pd

from nvd_coletas import selecionar_coleta_concluida


# ==========================================
# 1. LOCALIZAR A COLETA BRONZE
# ==========================================

pasta_coleta = selecionar_coleta_concluida(
    Path("data/bronze/nvd")
)

arquivos = sorted(
    pasta_coleta.glob("pagina_[0-9][0-9][0-9].json")
)

if not arquivos:
    raise FileNotFoundError(
        "Nenhuma página JSON encontrada."
    )


# ==========================================
# 2. EXTRAIR ASSOCIAÇÕES CVE-CWE
# ==========================================

registros = []
total_cves = 0

for caminho in arquivos:

    with caminho.open(
        "r",
        encoding="utf-8"
    ) as arquivo:
        dados = json.load(arquivo)

    for item in dados["vulnerabilities"]:

        cve = item["cve"]
        cve_id = cve["id"]

        total_cves += 1

        weaknesses = cve.get("weaknesses") or []

        for weakness in weaknesses:

            descricoes = weakness.get(
                "description", []
            )

            for descricao in descricoes:

                codigo = descricao.get("value")

                if not isinstance(codigo, str):
                    continue

                codigo = codigo.strip()

                # Aceitar somente CWE numérica
                if not re.fullmatch(
                    r"CWE-\d+",
                    codigo
                ):
                    continue

                registros.append({
                    "cve_id": cve_id,
                    "cwe_id": codigo
                })


# ==========================================
# 3. CRIAR DATAFRAME
# ==========================================

df = pd.DataFrame(
    registros,
    columns=["cve_id", "cwe_id"]
)

# Remover associações repetidas
df = df.drop_duplicates(
    subset=["cve_id", "cwe_id"]
)

# Ordenar para facilitar auditoria
df = df.sort_values(
    ["cve_id", "cwe_id"]
).reset_index(drop=True)


# ==========================================
# 4. VALIDAR
# ==========================================

assert total_cves == 2743

assert not df.empty

assert df["cve_id"].notna().all()

assert df["cwe_id"].notna().all()

assert not df.duplicated(
    subset=["cve_id", "cwe_id"]
).any()

# Conferir existência das CVEs na Silver
arquivo_cves = Path(
    "data/silver/nvd/silver_cves.parquet"
)

df_cves = pd.read_parquet(
    arquivo_cves,
    columns=["cve_id"]
)

assert df["cve_id"].isin(
    df_cves["cve_id"]
).all()


# ==========================================
# 5. SALVAR PARQUET
# ==========================================

pasta_saida = Path("data/silver/nvd")

pasta_saida.mkdir(
    parents=True,
    exist_ok=True
)

arquivo_saida = (
    pasta_saida / "silver_cwe.parquet"
)

df.to_parquet(
    arquivo_saida,
    index=False
)


# ==========================================
# 6. RELATÓRIO
# ==========================================

cves_com_cwe = df["cve_id"].nunique()

cves_sem_cwe = total_cves - cves_com_cwe

quantidade_por_cve = df.groupby(
    "cve_id"
).size()

cves_multiplas = int(
    (quantidade_por_cve > 1).sum()
)

print("Coleta:", pasta_coleta.name)

print("\nCONSTRUÇÃO SILVER — CWE")

print("CVEs analisadas:", total_cves)

print(
    "Associações CVE-CWE:",
    len(df)
)

print(
    "CVEs com CWE:",
    cves_com_cwe
)

print(
    "CVEs sem CWE:",
    cves_sem_cwe
)

print(
    "CVEs com múltiplas CWE:",
    cves_multiplas
)

print(
    "Códigos CWE distintos:",
    df["cwe_id"].nunique()
)

print("\nTOP 10 CWE")

print(
    df["cwe_id"]
    .value_counts()
    .head(10)
    .to_string()
)

print("\nArquivo gerado:", arquivo_saida)

print("\nSilver CWE: OK")
