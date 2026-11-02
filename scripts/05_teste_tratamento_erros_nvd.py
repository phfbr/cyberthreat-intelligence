
import time
import requests

# Endpoint oficial da API NVD
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Configuração de tentativas
MAX_TENTATIVAS = 3
INTERVALO = 6

# Parâmetros da consulta
parametros = {
    "cveId": "CVE-2021-44228"
}

def consultar_nvd(url, parametros):
    for tentativa in range(1, MAX_TENTATIVAS + 1):

        try:
            print(f"Tentativa {tentativa}/{MAX_TENTATIVAS}")

            resposta = requests.get(
                url,
                params=parametros,
                headers={
                    "User-Agent": "CyberThreatIntelligence-Learning/1.0"
                },
                timeout=30
            )

            # Identificar erros temporários
            if resposta.status_code in [429, 500, 502, 503, 504]:
                print("Erro temporário:", resposta.status_code)

                if tentativa < MAX_TENTATIVAS:
                    time.sleep(INTERVALO)
                    continue

            # Identificar outros erros HTTP
            resposta.raise_for_status()

            print("Consulta realizada com sucesso!")
            return resposta.json()

        except (requests.exceptions.Timeout,
                requests.exceptions.ConnectionError) as erro:

            print("Falha de comunicação:", erro)

            if tentativa < MAX_TENTATIVAS:
                time.sleep(INTERVALO)

        except requests.exceptions.HTTPError as erro:
            print("Erro HTTP:", erro)
            raise

    raise RuntimeError(
        "Não foi possível consultar a NVD após as tentativas."
    )


# Executar somente quando este arquivo for iniciado diretamente
if __name__ == "__main__":

    dados = consultar_nvd(URL, parametros)

    cve = dados["vulnerabilities"][0]["cve"]

    print("\nRESULTADO")
    print("CVE:", cve["id"])
    print("Status da vulnerabilidade:", cve["vulnStatus"])