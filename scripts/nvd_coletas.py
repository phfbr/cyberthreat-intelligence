
import json
from pathlib import Path


def selecionar_coleta_concluida(pasta_nvd):
    """
    Localiza a coleta mais recente com status 'concluida'.

    Parâmetro:
        pasta_nvd: diretório que contém as coletas.

    Retorno:
        Path da coleta selecionada.
    """

    pasta_nvd = Path(pasta_nvd)

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
        "Nenhuma coleta concluída foi encontrada."
    )
