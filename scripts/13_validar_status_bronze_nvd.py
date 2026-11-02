
import json
from pathlib import Path


# ==========================================
# LOCALIZAR A COLETA
# ==========================================

pasta_nvd = Path("data/bronze/nvd")

pastas = sorted(
    pasta
    for pasta in pasta_nvd.glob("coleta_*")
    if pasta.is_dir()
)

if not pastas:
    raise FileNotFoundError(
        "Nenhuma pasta de coleta encontrada."
    )

pasta_coleta = pastas[-1]

print("Coleta selecionada:", pasta_coleta.name)


# ==========================================
# LER O ARQUIVO DE STATUS
# ==========================================

arquivo_status = pasta_coleta / "status_coleta.json"

if not arquivo_status.exists():
    raise FileNotFoundError(
        "Arquivo status_coleta.json não encontrado."
    )

with arquivo_status.open("r", encoding="utf-8") as arquivo:
    status = json.load(arquivo)


# ==========================================
# CONFERIR OS ARQUIVOS DA BRONZE
# ==========================================

arquivos_paginas = sorted(
    pasta_coleta.glob("pagina_[0-9][0-9][0-9].json")
)

total_registros = 0

for arquivo_pagina in arquivos_paginas:

    with arquivo_pagina.open("r", encoding="utf-8") as arquivo:
        dados = json.load(arquivo)

    total_registros += len(dados["vulnerabilities"])


# ==========================================
# VALIDAR O CONTROLE
# ==========================================

assert status["status"] == "concluida", (
    "A coleta não está marcada como concluída."
)

assert status["paginas_coletadas"] == len(arquivos_paginas), (
    "Quantidade de páginas inconsistente."
)

assert status["registros_coletados"] == total_registros, (
    "Quantidade de registros inconsistente."
)

assert status["paginas_previstas"] == len(arquivos_paginas), (
    "A coleta possui menos páginas que o previsto."
)


# ==========================================
# RESULTADO
# ==========================================

print("\nRESULTADO DA VALIDAÇÃO")
print("Status:", status["status"])
print("Páginas previstas:", status["paginas_previstas"])
print("Páginas encontradas:", len(arquivos_paginas))
print("Registros confirmados:", total_registros)
print("Validação do controle: OK")
