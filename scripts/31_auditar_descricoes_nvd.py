
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
# CONTADORES
# ==========================================

total_cves = 0

com_descricao = 0
sem_descricao = 0

com_ingles = 0
sem_ingles = 0

idiomas = Counter()
quantidades_por_cve = Counter()

descricoes_vazias = 0
exemplos_sem_ingles = []


# ==========================================
# ANALISAR DESCRIÇÕES
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

        descricoes = cve.get("descriptions") or []

        descricoes_validas = []

        for descricao in descricoes:

            if not isinstance(descricao, dict):
                continue

            idioma = descricao.get("lang")
            texto = descricao.get("value")

            if not isinstance(texto, str) or not texto.strip():
                descricoes_vazias += 1
                continue

            descricoes_validas.append(descricao)
            idiomas[idioma or "NAO_INFORMADO"] += 1

        quantidades_por_cve[
            len(descricoes_validas)
        ] += 1

        if descricoes_validas:
            com_descricao += 1
        else:
            sem_descricao += 1

        possui_ingles = any(
            descricao.get("lang") == "en"
            for descricao in descricoes_validas
        )

        if possui_ingles:
            com_ingles += 1
        else:
            sem_ingles += 1

            if len(exemplos_sem_ingles) < 10:
                exemplos_sem_ingles.append(
                    cve["id"]
                )


# ==========================================
# RELATÓRIO
# ==========================================

print("Coleta:", pasta_coleta.name)

print("\nAUDITORIA DE DESCRIÇÕES")

print("Total de CVEs:", total_cves)
print("Com descrição válida:", com_descricao)
print("Sem descrição válida:", sem_descricao)

print("Com descrição em inglês:", com_ingles)
print("Sem descrição em inglês:", sem_ingles)

print(
    "Entradas de descrição vazias:",
    descricoes_vazias
)

print("\nIDIOMAS ENCONTRADOS")

for idioma, quantidade in idiomas.most_common():
    print(f"{idioma}: {quantidade}")

print("\nDESCRIÇÕES VÁLIDAS POR CVE")

for quantidade, cves in sorted(
    quantidades_por_cve.items()
):
    print(
        f"{quantidade} descrição(ões): {cves} CVEs"
    )

print("\nEXEMPLOS SEM INGLÊS")

for identificador in exemplos_sem_ingles:
    print(identificador)


# ==========================================
# VALIDAÇÕES
# ==========================================

assert total_cves == com_descricao + sem_descricao

assert total_cves == com_ingles + sem_ingles

assert sum(quantidades_por_cve.values()) == total_cves

print("\nAuditoria de descrições: OK")
