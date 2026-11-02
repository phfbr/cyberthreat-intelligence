
import json
from collections import defaultdict
from pathlib import Path

from nvd_coletas import selecionar_coleta_concluida


# Localizar coleta concluída
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


def extrair_matches(elemento):
    """Localiza cpeMatch em estruturas aninhadas."""

    if isinstance(elemento, dict):

        for match in elemento.get("cpeMatch", []):
            if isinstance(match, dict):
                yield match

        for chave, valor in elemento.items():
            if chave != "cpeMatch":
                yield from extrair_matches(valor)

    elif isinstance(elemento, list):

        for item in elemento:
            yield from extrair_matches(item)


# Cada fabricante terá um conjunto de IDs CVE
cves_por_fabricante = defaultdict(set)
cves_vulneraveis_por_fabricante = defaultdict(set)

total_cves = 0
cves_com_fabricante = set()


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

        configuracoes = cve.get(
            "configurations"
        ) or []

        for match in extrair_matches(configuracoes):

            criterio = match.get("criteria", "")

            partes = criterio.split(":")

            if (
                len(partes) < 5
                or partes[0] != "cpe"
                or partes[1] != "2.3"
            ):
                continue

            fabricante = partes[3]

            cves_por_fabricante[
                fabricante
            ].add(cve_id)

            cves_com_fabricante.add(cve_id)

            if match.get("vulnerable") is True:

                cves_vulneraveis_por_fabricante[
                    fabricante
                ].add(cve_id)


# Relatório
print("Coleta:", pasta_coleta.name)

print("\nAUDITORIA DE CVEs POR FABRICANTE")

print("Total de CVEs:", total_cves)

print(
    "CVEs com fabricante identificado:",
    len(cves_com_fabricante)
)

print("\nTOP 20 FABRICANTES")

ranking = sorted(
    cves_por_fabricante.items(),
    key=lambda item: (-len(item[1]), item[0])
)

for fabricante, cves in ranking[:20]:

    total = len(cves)

    vulneraveis = len(
        cves_vulneraveis_por_fabricante[
            fabricante
        ]
    )

    print(
        f"{fabricante}: "
        f"{total} CVEs distintas | "
        f"{vulneraveis} com CPE vulnerable=True"
    )


# Validações
assert total_cves == 2743

assert len(cves_com_fabricante) <= total_cves

assert all(
    cves_vulneraveis_por_fabricante[fabricante]
    <= cves
    for fabricante, cves
    in cves_por_fabricante.items()
)

print("\nAuditoria por fabricante: OK")
