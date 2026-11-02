
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from nvd_coletas import selecionar_coleta_concluida


# Criar um ambiente temporário para o teste
with TemporaryDirectory() as diretorio:

    pasta_teste = Path(diretorio)

    # Simular uma coleta concluída
    coleta_concluida = (
        pasta_teste / "coleta_20261030_100000_000000"
    )
    coleta_concluida.mkdir()

    # Simular uma coleta mais recente com falha
    coleta_falhou = (
        pasta_teste / "coleta_20261030_110000_000000"
    )
    coleta_falhou.mkdir()

    # Criar os arquivos de controle
    for pasta, status in [
        (coleta_concluida, "concluida"),
        (coleta_falhou, "falhou")
    ]:

        arquivo_status = pasta / "status_coleta.json"

        with arquivo_status.open(
            "w",
            encoding="utf-8"
        ) as arquivo:
            json.dump(
                {"status": status},
                arquivo
            )

    # Executar a função real do módulo
    selecionada = selecionar_coleta_concluida(
        pasta_teste
    )

    # Confirmar que a coleta com falha foi ignorada
    assert selecionada == coleta_concluida, (
        "A função selecionou uma coleta incorreta."
    )

    print("RESULTADO DO TESTE")
    print("Coleta mais recente:", coleta_falhou.name)
    print("Status mais recente: falhou")
    print("Coleta selecionada:", selecionada.name)
    print("Status selecionado: concluida")
    print("Teste do módulo compartilhado: OK")
