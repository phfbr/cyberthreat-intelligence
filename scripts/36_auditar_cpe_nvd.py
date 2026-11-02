
import json
from collections import Counter
from pathlib import Path

from nvd_coletas import selecionar_coleta_concluida


# ==========================================
# LOCALIZAR COLETA
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
# FUNÇÃO PARA LOCALIZAR CPEs
# ==========================================

def extrair_cpe_matches(elemento):
    """
    Percorre estruturas aninhadas e retorna
    objetos cpeMatch encontrados.
    """

    if isinstance(elemento, dict):

        matches = elemento.get("cpeMatch", [])

        if isinstance(matches, list):
            for match in matches:
                if isinstance(match, dict):
                    yield match

        for chave, valor in elemento.items():

            if chave != "cpeMatch":
                yield from extrair_cpe_matches(valor)

    elif isinstance(elemento, list):

        for item in elemento:
            yield from extrair_cpe_matches(item)


# ==========================================
# CONTADORES
# ==========================================

total_cves = 0
com_configuracoes = 0
sem_configuracoes = 0

com_cpe = 0
sem_cpe = 0

total_matches = 0
matches_vulneraveis = 0
matches_nao_vulneraveis = 0

fabricantes = Counter()
produtos = Counter()
tipos = Counter()

exemplos = []


# ==========================================
# AUDITORIA
# ==========================================

for caminho in arquivos:

    with caminho.open(
        "r",
        encoding="utf-8"
    ) as arquivo:
        dados = json.load(arquivo)

    for item in dados["vulnerabilities"]:

        cve = item["cve"]
        total_cves += 1

        configuracoes = cve.get(
            "configurations"
        ) or []

        if configuracoes:
            com_configuracoes += 1
        else:
            sem_configuracoes += 1

        matches = list(
            extrair_cpe_matches(configuracoes)
        )

        if matches:
            com_cpe += 1
        else:
            sem_cpe += 1

        for match in matches:

            total_matches += 1

            if match.get("vulnerable") is True:
                matches_vulneraveis += 1
            else:
                matches_nao_vulneraveis += 1

            criterios = match.get(
                "criteria", ""
            )

            partes = criterios.split(":")

            # Formato esperado:
            # cpe:2.3:tipo:fabricante:produto:...

            if (
                len(partes) >= 5
                and partes[0] == "cpe"
                and partes[1] == "2.3"
            ):

                tipo = partes[2]
                fabricante = partes[3]
                produto = partes[4]

                tipos[tipo] += 1
                fabricantes[fabricante] += 1

                produtos[
                    (fabricante, produto)
                ] += 1

                if len(exemplos) < 10:
                    exemplos.append({
                        "cve": cve["id"],
                        "cpe": criterios,
                        "vulnerable": match.get(
                            "vulnerable"
                        )
                    })


# ==========================================
# RELATÓRIO
# ==========================================

print("Coleta:", pasta_coleta.name)

print("\nAUDITORIA CPE")

print("Total de CVEs:", total_cves)

print(
    "CVEs com configurações:",
    com_configuracoes
)

print(
    "CVEs sem configurações:",
    sem_configuracoes
)

print("CVEs com CPE:", com_cpe)
print("CVEs sem CPE:", sem_cpe)

print("\nTOTAL DE CPE MATCHES")
print("Total:", total_matches)
print("Vulnerable=True:", matches_vulneraveis)
print("Demais valores:", matches_nao_vulneraveis)

print("\nTIPOS DE PLATAFORMA")

for tipo, quantidade in tipos.most_common():
    print(f"{tipo}: {quantidade}")

print("\nTOP 15 FABRICANTES")

for fabricante, quantidade in fabricantes.most_common(15):
    print(f"{fabricante}: {quantidade}")

print("\nTOP 15 PRODUTOS")

for (fabricante, produto), quantidade in produtos.most_common(15):
    print(
        f"{fabricante} / {produto}: {quantidade}"
    )

print("\nEXEMPLOS DE CPE")

for exemplo in exemplos:
    print(exemplo)


# ==========================================
# VALIDAÇÕES
# ==========================================

assert total_cves == 2743

assert (
    com_configuracoes + sem_configuracoes
    == total_cves
)

assert com_cpe + sem_cpe == total_cves

assert (
    matches_vulneraveis
    + matches_nao_vulneraveis
    == total_matches
)

print("\nAuditoria CPE: OK")
