
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
com_generica = 0
somente_generica = 0
com_especifica = 0
sem_classificacao = 0

codigos_genericos = Counter()

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

        codigos = set()

        for weakness in cve.get("weaknesses") or []:

            for descricao in weakness.get(
                "description", []
            ):

                codigo = descricao.get("value")

                if isinstance(codigo, str):
                    codigos.add(codigo.strip())

        genericos = {
            codigo
            for codigo in codigos
            if codigo in {
                "NVD-CWE-noinfo",
                "NVD-CWE-Other"
            }
        }

        especificos = {
            codigo
            for codigo in codigos
            if codigo.startswith("CWE-")
            and codigo[4:].isdigit()
        }

        if genericos:
            com_generica += 1

            for codigo in genericos:
                codigos_genericos[codigo] += 1

        if genericos and not especificos:
            somente_generica += 1

        if especificos:
            com_especifica += 1

        if not genericos and not especificos:
            sem_classificacao += 1

        if genericos and len(exemplos) < 10:
            exemplos.append({
                "cve": cve["id"],
                "genericos": sorted(genericos),
                "especificos": sorted(especificos)
            })


# ==========================================
# RELATÓRIO
# ==========================================

print("Coleta:", pasta_coleta.name)

print("\nAUDITORIA CWE GENÉRICAS")

print("Total de CVEs:", total_cves)
print("Com código genérico:", com_generica)
print("Somente código genérico:", somente_generica)
print("Com CWE específica:", com_especifica)
print("Sem classificação:", sem_classificacao)

print("\nCÓDIGOS GENÉRICOS")

for codigo, quantidade in codigos_genericos.items():
    print(f"{codigo}: {quantidade} CVEs")

print("\nEXEMPLOS")

for exemplo in exemplos:
    print(exemplo)


# ==========================================
# VALIDAÇÕES
# ==========================================

assert total_cves == 2743

assert (
    total_cves
    == com_especifica
    + somente_generica
    + sem_classificacao
)

print("\nAuditoria CWE genéricas: OK")
