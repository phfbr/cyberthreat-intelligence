
import json
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory


def registrar_status(pasta, status, paginas, registros):
    """Registra o estado de uma execução de coleta."""

    if status not in {"concluida", "falhou"}:
        raise ValueError("Status de coleta inválido")

    controle = {
        "fonte": "NIST NVD",
        "status": status,
        "paginas_coletadas": paginas,
        "registros_coletados": registros,
        "atualizado_em_utc": datetime.now(
            timezone.utc
        ).isoformat()
    }

    arquivo = pasta / "status_coleta.json"

    with arquivo.open("w", encoding="utf-8") as f:
        json.dump(
            controle,
            f,
            indent=4,
            ensure_ascii=False
        )

    return arquivo


# Testar sem modificar os dados reais da Bronze
with TemporaryDirectory() as diretorio:
    pasta_teste = Path(diretorio)

    arquivo = registrar_status(
        pasta=pasta_teste,
        status="concluida",
        paginas=2,
        registros=10
    )

    with arquivo.open("r", encoding="utf-8") as f:
        resultado = json.load(f)

    assert resultado["status"] == "concluida"
    assert resultado["paginas_coletadas"] == 2
    assert resultado["registros_coletados"] == 10

    print("RESULTADO DO TESTE")
    print("Status:", resultado["status"])
    print("Páginas:", resultado["paginas_coletadas"])
    print("Registros:", resultado["registros_coletados"])
    print("Arquivo de controle: OK")
    print("Teste de registro de status: OK")
