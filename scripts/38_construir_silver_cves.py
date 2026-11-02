
import json
from pathlib import Path

import pandas as pd

from cvss_selecao import selecionar_cvss_referencia
from nvd_coletas import selecionar_coleta_concluida


# ==========================================
# 1. LOCALIZAR OS DADOS BRONZE
# ==========================================

pasta_coleta = selecionar_coleta_concluida(
    Path("data/bronze/nvd")
)

arquivos = sorted(
    pasta_coleta.glob("pagina_[0-9][0-9][0-9].json")
)

if not arquivos:
    raise FileNotFoundError(
        "Nenhum arquivo JSON encontrado."
    )


# ==========================================
# 2. FUNÇÃO PARA EXTRAIR DESCRIÇÃO
# ==========================================

def obter_descricao_ingles(descricoes):

    for descricao in descricoes:

        if descricao.get("lang") == "en":
            return descricao.get("value")

    return None


# ==========================================
# 3. EXTRAIR OS REGISTROS
# ==========================================

registros = []

for caminho in arquivos:

    with caminho.open(
        "r",
        encoding="utf-8"
    ) as arquivo:
        dados = json.load(arquivo)

    for item in dados["vulnerabilities"]:

        cve = item["cve"]

        cvss = selecionar_cvss_referencia(
            cve.get("metrics", {})
        )

        registro = {
            "cve_id": cve.get("id"),
            "data_publicacao": cve.get("published"),
            "data_modificacao": cve.get("lastModified"),
            "status_nvd": cve.get("vulnStatus"),
            "flag_rejeitada": (
                cve.get("vulnStatus") == "Rejected"
            ),
            "descricao_en": obter_descricao_ingles(
                cve.get("descriptions", [])
            ),
            "cvss_referencia_versao": (
                cvss["versao"] if cvss else None
            ),
            "cvss_referencia_pontuacao": (
                cvss["pontuacao"] if cvss else None
            ),
            "cvss_referencia_severidade": (
                cvss["severidade"] if cvss else None
            ),
            "cvss_referencia_fonte": (
                cvss["fonte"] if cvss else None
            ),
            "cvss_referencia_tipo": (
                cvss["tipo"] if cvss else None
            ),
        }

        registros.append(registro)


# ==========================================
# 4. CRIAR DATAFRAME
# ==========================================

df = pd.DataFrame(registros)

# Converter datas para datetime em UTC
df["data_publicacao"] = pd.to_datetime(
    df["data_publicacao"],
    utc=True,
    errors="raise"
)

df["data_modificacao"] = pd.to_datetime(
    df["data_modificacao"],
    utc=True,
    errors="raise"
)

# Converter pontuação para número
df["cvss_referencia_pontuacao"] = pd.to_numeric(
    df["cvss_referencia_pontuacao"],
    errors="raise"
)


# ==========================================
# 5. VALIDAR ANTES DE SALVAR
# ==========================================

assert len(df) == 2743, (
    "Quantidade de CVEs inesperada."
)

assert df["cve_id"].notna().all(), (
    "Existem CVEs sem identificador."
)

assert df["cve_id"].is_unique, (
    "Existem identificadores CVE duplicados."
)

assert df["data_publicacao"].notna().all(), (
    "Existem datas de publicação inválidas."
)

assert df["data_modificacao"].notna().all(), (
    "Existem datas de modificação inválidas."
)

assert df["status_nvd"].notna().all(), (
    "Existem CVEs sem status."
)

assert df["descricao_en"].notna().all(), (
    "Existem CVEs sem descrição em inglês."
)


# ==========================================
# 6. SALVAR NA CAMADA SILVER
# ==========================================

pasta_saida = Path("data/silver/nvd")
pasta_saida.mkdir(
    parents=True,
    exist_ok=True
)

arquivo_saida = (
    pasta_saida / "silver_cves.parquet"
)

df.to_parquet(
    arquivo_saida,
    index=False
)


# ==========================================
# 7. RELATÓRIO
# ==========================================

print("Coleta:", pasta_coleta.name)

print("\nCONSTRUÇÃO SILVER — CVEs")

print("Registros:", len(df))
print("Colunas:", len(df.columns))

print(
    "CVEs rejeitadas:",
    int(df["flag_rejeitada"].sum())
)

print(
    "CVEs com CVSS:",
    int(
        df["cvss_referencia_pontuacao"]
        .notna()
        .sum()
    )
)

print(
    "CVEs sem CVSS:",
    int(
        df["cvss_referencia_pontuacao"]
        .isna()
        .sum()
    )
)

print("\nArquivo gerado:", arquivo_saida)

print("\nSilver CVEs: OK")
