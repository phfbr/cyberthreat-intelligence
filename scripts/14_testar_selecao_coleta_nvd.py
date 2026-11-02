
import json
from pathlib import Path
from tempfile import TemporaryDirectory


def selecionar_coleta_concluida(pasta_nvd):

    pastas = sorted(
        (
            pasta
            for pasta in pasta_nvd.glob("coleta_*")
            if pasta.is_dir()
        ),
        reverse=True
    )

    for pasta in pastas:

        arquivo_status = pasta / "status_coleta.json"

        if not arquivo_status.is_file():
            continue

        try:
            with arquivo_status.open(
                "r",
                encoding="utf-8"
            ) as arquivo:
                controle = json.load(arquivo)

        except (OSError, json.JSONDecodeError):
            continue

        if controle.get("status") == "concluida":
            return pasta

    raise FileNotFoundError(
        "Nenhuma coleta concluída encontrada."
    )


# ==========================================
# CRIAR AMBIENTE DE TESTE TEMPORÁRIO
# ==========================================

with TemporaryDirectory() as diretorio:

    pasta_teste = Path(diretorio)

    # Coleta antiga, concluída
    coleta_valida = (
        pasta_teste / "coleta_20261030_100000_000000"
    )
    coleta_valida.mkdir()

    # Coleta mais recente, interrompida
    coleta_falha = (
        pasta_teste / "coleta_20261030_110000_000000"
    )
    coleta_falha.mkdir()

    # Registrar os estados simulados
    for pasta, estado in [
        (coleta_valida, "concluida"),
        (coleta_falha, "falhou")
    ]:

        with (
            pasta / "status_coleta.json"
        ).open("w", encoding="utf-8") as arquivo:

            json.dump(
                {"status": estado},
                arquivo
            )

    # Executar a seleção
    selecionada = selecionar_coleta_concluida(
        pasta_teste
    )

    # Verificar o resultado
    assert selecionada == coleta_valida, (
        "Uma coleta incorreta foi selecionada."
    )

    print("RESULTADO DO TESTE")
    print("Coleta mais recente:", coleta_falha.name)
    print("Status mais recente: falhou")
    print("Coleta selecionada:", selecionada.name)
    print("Status selecionado: concluida")
    print("Teste de seleção: OK")
