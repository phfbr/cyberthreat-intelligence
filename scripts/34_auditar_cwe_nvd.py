
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
        "Nenhuma página JSON encontrada na coleta."
    )


# ==========================================
# CONTADORES
# ==========================================

total_cves = 0
com_cwe = 0
sem_cwe = 0

frequencia_cwe = Counter()
quantidade_cwe_por_cve = Counter()

exemplos_sem_cwe = []


# ==========================================
# ANALISAR FRAQUEZAS
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

        weaknesses = cve.get("weaknesses") or []

        cwes_da_cve = set()

        for weakness in weaknesses:

            for descricao in weakness.get(
                "description", []
            ):

                codigo = descricao.get("value")

                if not isinstance(codigo, str):
                    continue

                codigo = codigo.strip()

                if codigo.startswith("CWE-"):
                    cwes_da_cve.add(codigo)

        if cwes_da_cve:
            com_cwe += 1
        else:
            sem_cwe += 1

            if len(exemplos_sem_cwe) < 10:
                exemplos_sem_cwe.append(cve["id"])

        quantidade_cwe_por_cve[
            len(cwes_da_cve)
        ] += 1

        # Contar cada CWE apenas uma vez por CVE
        for codigo in cwes_da_cve:
            frequencia_cwe[codigo] += 1


# ==========================================
# RELATÓRIO
# ==========================================

print("Coleta:", pasta_coleta.name)

print("\nAUDITORIA CWE")

print("Total de CVEs:", total_cves)
print("CVEs com código CWE:", com_cwe)
print("CVEs sem código CWE:", sem_cwe)

print("\nTOP 15 CWE")

for codigo, quantidade in frequencia_cwe.most_common(15):
    print(f"{codigo}: {quantidade} CVEs")

print("\nQUANTIDADE DE CWE POR CVE")

for quantidade, cves in sorted(
    quantidade_cwe_por_cve.items()
):
    print(
        f"{quantidade} CWE(s): {cves} CVEs"
    )

print("\nEXEMPLOS SEM CWE")

for identificador in exemplos_sem_cwe:
    print(identificador)


# ==========================================
# VALIDAÇÕES
# ==========================================

assert total_cves == com_cwe + sem_cwe

assert (
    sum(quantidade_cwe_por_cve.values())
    == total_cves
)

assert sum(frequencia_cwe.values()) == sum(
    quantidade * cves
    for quantidade, cves
    in quantidade_cwe_por_cve.items()
)

print("\nAuditoria CWE: OK")
