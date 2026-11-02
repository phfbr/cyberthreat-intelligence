
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import requests


# ==========================================
# CONFIGURAÇÕES
# ==========================================

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

REGISTROS_POR_PAGINA = 5
TOTAL_PAGINAS = 2

MAX_TENTATIVAS = 3
INTERVALO = 6

HEADERS = {
    "User-Agent": "CyberThreatIntelligence-Learning/1.0"
}


# ==========================================
# FUNÇÃO DE CONSULTA À API
# ==========================================

def consultar_nvd(parametros):

    erros_temporarios = {429, 500, 502, 503, 504}

    for tentativa in range(1, MAX_TENTATIVAS + 1):

        print(f"Tentativa {tentativa}/{MAX_TENTATIVAS}")

        try:
            resposta = requests.get(
                URL,
                params=parametros,
                headers=HEADERS,
                timeout=30
            )

            if resposta.status_code not in erros_temporarios:
                resposta.raise_for_status()
                return resposta

            print("Erro temporário:", resposta.status_code)

        except (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError
        ) as erro:
            print("Falha de comunicação:", erro)

        # Não aguardar depois da última tentativa
        if tentativa == MAX_TENTATIVAS:
            break

        # Espera progressiva: 6, 12, 24...
        tempo_espera = INTERVALO * (2 ** (tentativa - 1))

        # Respeitar Retry-After quando disponível
        if "resposta" in locals() and resposta is not None:
            if resposta.status_code in erros_temporarios:
                retry_after = resposta.headers.get("Retry-After")

                if retry_after and retry_after.isdigit():
                    tempo_espera = max(
                        tempo_espera,
                        int(retry_after)
                    )

        print(f"Aguardando {tempo_espera} segundos...")
        time.sleep(tempo_espera)

        # Limpar a resposta antes da próxima tentativa
        resposta = None

    raise RuntimeError(
        "Não foi possível consultar a NVD após "
        f"{MAX_TENTATIVAS} tentativas."
    )

# ==========================================

# ==========================================
# CONTROLE DO STATUS DA COLETA
# ==========================================

def registrar_status(pasta, status, paginas, registros):

    controle = {
        "fonte": "NIST NVD",
        "status": status,
        "paginas_coletadas": paginas,
        "registros_coletados": registros,
        "paginas_previstas": TOTAL_PAGINAS,
        "atualizado_em_utc": datetime.now(
            timezone.utc
        ).isoformat()
    }

    arquivo_status = pasta / "status_coleta.json"

    with arquivo_status.open(
        "w",
        encoding="utf-8"
    ) as arquivo:
        json.dump(
            controle,
            arquivo,
            indent=4,
            ensure_ascii=False
        )


# ==========================================
# PREPARAR A CAMADA BRONZE
# ==========================================

data_coleta = datetime.now(timezone.utc)

identificador_coleta = data_coleta.strftime(
    "%Y%m%d_%H%M%S_%f"
)

pasta_destino = (
    Path("data/bronze/nvd")
    / f"coleta_{identificador_coleta}"
)

pasta_destino.mkdir(
    parents=True,
    exist_ok=True
)

paginas_coletadas = 0
registros_coletados = 0

registrar_status(
    pasta_destino,
    "em_andamento",
    paginas_coletadas,
    registros_coletados
)


# ==========================================
# EXECUTAR A COLETA
# ==========================================

try:

    for pagina in range(TOTAL_PAGINAS):

        indice_inicial = pagina * REGISTROS_POR_PAGINA

        parametros = {
            "resultsPerPage": REGISTROS_POR_PAGINA,
            "startIndex": indice_inicial
        }

        print(f"\nConsultando página {pagina + 1}...")

        resposta = consultar_nvd(parametros)
        dados = resposta.json()

        if "vulnerabilities" not in dados:
            raise ValueError(
                "Resposta sem o campo vulnerabilities"
            )

        registros = dados["vulnerabilities"]

        if len(registros) != REGISTROS_POR_PAGINA:
            raise ValueError(
                "Quantidade inesperada de registros "
                f"na página {pagina + 1}"
            )

        if dados.get("startIndex") != indice_inicial:
            raise ValueError(
                "Índice inicial inconsistente "
                f"na página {pagina + 1}"
            )

        arquivo_dados = (
            pasta_destino
            / f"pagina_{pagina + 1:03d}.json"
        )

        with arquivo_dados.open("wb") as arquivo:
            arquivo.write(resposta.content)

        metadados = {
            "fonte": "NIST NVD",
            "endpoint": URL,
            "data_coleta_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "indice_inicial": indice_inicial,
            "quantidade_registros": len(registros),
            "status_http": resposta.status_code,
            "arquivo_dados": arquivo_dados.name,
            "tamanho_bytes": arquivo_dados.stat().st_size
        }

        arquivo_metadados = (
            pasta_destino
            / f"pagina_{pagina + 1:03d}_metadata.json"
        )

        with arquivo_metadados.open(
            "w",
            encoding="utf-8"
        ) as arquivo:
            json.dump(
                metadados,
                arquivo,
                indent=4,
                ensure_ascii=False
            )

        paginas_coletadas += 1
        registros_coletados += len(registros)

        registrar_status(
            pasta_destino,
            "em_andamento",
            paginas_coletadas,
            registros_coletados
        )

        print("Registros:", len(registros))
        print("Arquivo:", arquivo_dados.name)

        if pagina < TOTAL_PAGINAS - 1:
            time.sleep(INTERVALO)

    registrar_status(
        pasta_destino,
        "concluida",
        paginas_coletadas,
        registros_coletados
    )

    print("\nCOLETA FINALIZADA")
    print("Páginas:", paginas_coletadas)
    print("Registros:", registros_coletados)
    print("Status: concluida")
    print("Pasta:", pasta_destino)

except Exception as erro:

    registrar_status(
        pasta_destino,
        "falhou",
        paginas_coletadas,
        registros_coletados
    )

    print("\nCOLETA INTERROMPIDA")
    print("Status: falhou")
    print("Erro:", erro)
    print("Pasta:", pasta_destino)

    raise
