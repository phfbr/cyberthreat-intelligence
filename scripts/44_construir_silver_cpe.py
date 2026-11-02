
import json
from pathlib import Path

import pandas as pd

from nvd_coletas import selecionar_coleta_concluida


# ==========================================
# 1. LOCALIZAR A COLETA
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
# 2. PERCORRER NÓS DE CONFIGURAÇÃO
# ==========================================

def percorrer_nos(elemento, caminho=""):
    """
    Percorre objetos e listas, preservando
    o caminho de cada nó encontrado.
    """

    if isinstance(elemento, dict):

        if "cpeMatch" in elemento:
            yield caminho, elemento

        for chave, valor in elemento.items():

            if chave != "cpeMatch":
                novo_caminho = (
                    f"{caminho}/{chave}"
                )
                yield from percorrer_nos(
                    valor,
                    novo_caminho
                )

    elif isinstance(elemento, list):

        for indice, item in enumerate(elemento):
            yield from percorrer_nos(
                item,
                f"{caminho}/{indice}"
            )


# ==========================================
# 3. EXTRAIR CPEs
# ==========================================

registros = []
total_cves = 0

for arquivo in arquivos:

    with arquivo.open(
        "r",
        encoding="utf-8"
    ) as f:
        dados = json.load(f)

    for item in dados["vulnerabilities"]:

        cve = item["cve"]
        cve_id = cve["id"]
        total_cves += 1

        configuracoes = cve.get(
            "configurations"
        ) or []

        for caminho, no in percorrer_nos(
            configuracoes,
            "configurations"
        ):

            matches = no.get("cpeMatch") or []

            for indice, match in enumerate(matches):

                criterio = match.get(
                    "criteria", ""
                )

                partes = criterio.split(":")

                tipo = None
                fabricante = None
                produto = None

                if (
                    len(partes) >= 5
                    and partes[0] == "cpe"
                    and partes[1] == "2.3"
                ):
                    tipo = partes[2]
                    fabricante = partes[3]
                    produto = partes[4]

                registros.append({
                    "cve_id": cve_id,
                    "cpe_criteria": criterio,
                    "tipo_plataforma": tipo,
                    "fabricante": fabricante,
                    "produto": produto,
                    "vulnerable": match.get(
                        "vulnerable"
                    ),
                    "match_criteria_id": match.get(
                        "matchCriteriaId"
                    ),
                    "version_start_including": match.get(
                        "versionStartIncluding"
                    ),
                    "version_start_excluding": match.get(
                        "versionStartExcluding"
                    ),
                    "version_end_including": match.get(
                        "versionEndIncluding"
                    ),
                    "version_end_excluding": match.get(
                        "versionEndExcluding"
                    ),
                    "caminho_configuracao": caminho,
                    "indice_match": indice,
                    "operador_no": no.get(
                        "operator"
                    ),
                    "negacao_no": no.get(
                        "negate"
                    ),
                })


# ==========================================
# 4. CRIAR DATAFRAME
# ==========================================

df = pd.DataFrame(registros)

df = df.sort_values(
    [
        "cve_id",
        "caminho_configuracao",
        "indice_match",
    ]
).reset_index(drop=True)


# ==========================================
# 5. VALIDAÇÕES INICIAIS
# ==========================================

assert total_cves == 2743

assert len(df) == 8180

assert df["cve_id"].nunique() == 715

assert df["cve_id"].notna().all()

assert df["cpe_criteria"].notna().all()

assert not df.duplicated(
    subset=[
        "cve_id",
        "caminho_configuracao",
        "indice_match",
    ]
).any()


# ==========================================
# 6. SALVAR PARQUET
# ==========================================

pasta_saida = Path("data/silver/nvd")

pasta_saida.mkdir(
    parents=True,
    exist_ok=True
)

arquivo_saida = (
    pasta_saida / "silver_cpe.parquet"
)

df.to_parquet(
    arquivo_saida,
    index=False
)


# ==========================================
# 7. RELATÓRIO
# ==========================================

print("Coleta:", pasta_coleta.name)

print("\nCONSTRUÇÃO SILVER — CPE")

print("CVEs analisadas:", total_cves)
print("Registros CPE:", len(df))

print(
    "CVEs com CPE:",
    df["cve_id"].nunique()
)

print(
    "Fabricantes distintos:",
    df["fabricante"].nunique()
)

print(
    "Produtos distintos:",
    df[
        ["fabricante", "produto"]
    ].drop_duplicates().shape[0]
)

print("\nTIPOS DE PLATAFORMA")

print(
    df["tipo_plataforma"]
    .value_counts(dropna=False)
    .to_string()
)

print("\nArquivo gerado:", arquivo_saida)

print("\nSilver CPE: OK")
