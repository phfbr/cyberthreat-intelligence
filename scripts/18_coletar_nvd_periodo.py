
import json
import math
import time
from datetime import datetime, timezone
from pathlib import Path

import requests


# ==========================================
# CONFIGURAÇÕES
# ==========================================

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DATA_INICIO = "2026-10-01T00:00:00.000Z"
DATA_FIM = "2026-10-07T23:59:59.999Z"

REGISTROS_POR_PAGINA = 2000
MAX_TENTATIVAS = 3
INTERVALO = 6

HEADERS = {
    "User-Agent": "CyberThreatIntelligence-Learning/1.0"
}


# ==========================================
# CONSULTAR A API
# ==========================================

def consultar_nvd(parametros):

    erros_temporarios = {429, 500, 502, 503, 504}

    for tentativa in range(1, MAX_TENTATIVAS + 1):

        print(f"Tentativa {tentativa}/{MAX_TENTATIVAS}")

        resposta = None

        try:
            resposta = requests.get(
                URL,
                params=parametros,
                headers=HEADERS,
                timeout=120
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

        if tentativa == MAX_TENTATIVAS:
            break

        tempo_espera = INTERVALO * (2 ** (tentativa - 1))

        if resposta is not None:
            retry_after = resposta.headers.get("Retry-After")

            if retry_after and retry_after.isdigit():
                tempo_espera = max(
                    tempo_espera,
                    int(retry_after)
                )

        print(f"Aguardando {tempo_espera} segundos...")
        time.sleep(tempo_espera)

    raise RuntimeError(
        "Consulta NVD falhou após três tentativas."
    )


# ==========================================
# REGISTRAR STATUS
# ==========================================

def registrar_status(pasta, status, paginas, registros):

    controle = {
        "fonte": "NIST NVD",
        "tipo_coleta": "publicacao",
        "periodo_inicio": DATA_INICIO,
        "periodo_fim": DATA_FIM,
        "status": status,
        "paginas_coletadas": paginas,
        "registros_coletados": registros,
        "atualizado_em_utc": datetime.now(
            timezone.utc
        ).isoformat()
    }

    with (
        pasta / "status_coleta.json"
    ).open("w", encoding="utf-8") as arquivo:

        json.dump(
            controle,
            arquivo,
            indent=4,
            ensure_ascii=False
        )


# ==========================================
# PREPARAR A COLETA
# ==========================================

identificador = datetime.now(
    timezone.utc
).strftime("%Y%m%d_%H%M%S_%f")

pasta_destino = (
    Path("data/bronze/nvd")
    / f"coleta_{identificador}"
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
# EXECUTAR COLETA TEMPORAL
# ==========================================

try:

    parametros = {
        "pubStartDate": DATA_INICIO,
        "pubEndDate": DATA_FIM,
        "resultsPerPage": REGISTROS_POR_PAGINA,
        "startIndex": 0
    }

    print("\nConsultando primeira página...")

    resposta_inicial = consultar_nvd(parametros)
    dados_iniciais = resposta_inicial.json()

    total_esperado = dados_iniciais["totalResults"]

    total_paginas = math.ceil(
        total_esperado / REGISTROS_POR_PAGINA
    )

    print("Total informado pela NVD:", total_esperado)
    print("Páginas previstas:", total_paginas)

    for pagina in range(total_paginas):

        indice_inicial = pagina * REGISTROS_POR_PAGINA

        if pagina == 0:
            resposta = resposta_inicial
            dados = dados_iniciais

        else:
            parametros["startIndex"] = indice_inicial

            print(f"\nConsultando página {pagina + 1}...")

            time.sleep(INTERVALO)

            resposta = consultar_nvd(parametros)
            dados = resposta.json()

        registros = dados["vulnerabilities"]

        if dados["startIndex"] != indice_inicial:
            raise ValueError(
                "Índice inicial inconsistente."
            )

        quantidade_prevista = min(
            REGISTROS_POR_PAGINA,
            total_esperado - indice_inicial
        )

        if len(registros) != quantidade_prevista:
            raise ValueError(
                "Quantidade inesperada de registros "
                f"na página {pagina + 1}."
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
            "periodo_inicio": DATA_INICIO,
            "periodo_fim": DATA_FIM,
            "data_coleta_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "indice_inicial": indice_inicial,
            "quantidade_registros": len(registros),
            "total_resultados_inicial": total_esperado,
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

        print(
            f"Página {pagina + 1}: "
            f"{len(registros)} registros armazenados"
        )

    if registros_coletados != total_esperado:
        raise ValueError(
            "Total coletado diferente do total esperado."
        )

    registrar_status(
        pasta_destino,
        "concluida",
        paginas_coletadas,
        registros_coletados
    )

    print("\nCOLETA TEMPORAL FINALIZADA")
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
    print("Erro:", erro)
    print("Pasta:", pasta_destino)

    raise
