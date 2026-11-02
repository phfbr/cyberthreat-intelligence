
import json
import math


# Ordem de preferência das versões CVSS
VERSOES_CVSS = [
    "cvssMetricV40",
    "cvssMetricV31",
    "cvssMetricV30",
    "cvssMetricV2"
]


def selecionar_cvss_referencia(metrics):
    """
    Seleciona uma avaliação CVSS de referência.

    Retorna um dicionário com os dados selecionados
    ou None quando não existe avaliação válida.
    """

    if not isinstance(metrics, dict):
        return None

    candidatos = []

    for prioridade_versao, versao in enumerate(
        VERSOES_CVSS
    ):

        avaliacoes = metrics.get(versao, [])

        if not isinstance(avaliacoes, list):
            continue

        for avaliacao in avaliacoes:

            if not isinstance(avaliacao, dict):
                continue

            dados_cvss = avaliacao.get("cvssData") or {}

            if not isinstance(dados_cvss, dict):
                continue

            pontuacao = dados_cvss.get("baseScore")

            # Rejeitar valores inválidos e booleanos
            if (
                isinstance(pontuacao, bool)
                or not isinstance(pontuacao, (int, float))
                or not math.isfinite(pontuacao)
                or not 0 <= pontuacao <= 10
            ):
                continue

            fonte = avaliacao.get("source")
            tipo = avaliacao.get("type")
            vetor = dados_cvss.get("vectorString")

            # Critérios de prioridade
            prioridade_tipo = (
                0 if tipo == "Primary" else 1
            )

            prioridade_fonte = (
                0 if fonte == "nvd@nist.gov" else 1
            )

            # Desempate determinístico
            desempate = json.dumps(
                avaliacao,
                sort_keys=True,
                ensure_ascii=False
            )

            chave_ordenacao = (
                prioridade_versao,
                prioridade_tipo,
                prioridade_fonte,
                str(fonte or ""),
                str(vetor or ""),
                desempate
            )

            candidatos.append(
                (
                    chave_ordenacao,
                    {
                        "versao": dados_cvss.get("version"),
                        "metrica": versao,
                        "pontuacao": pontuacao,
                        "severidade": (
                            dados_cvss.get("baseSeverity")
                            or avaliacao.get("baseSeverity")
                        ),
                        "fonte": fonte,
                        "tipo": tipo,
                        "vetor": vetor,
                        "regra": "CVSS_REFERENCIA_V1"
                    }
                )
            )

    if not candidatos:
        return None

    candidatos.sort(key=lambda item: item[0])

    return candidatos[0][1]
