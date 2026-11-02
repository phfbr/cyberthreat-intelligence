
import importlib.util
from pathlib import Path
from unittest.mock import Mock, patch

# Localizar o script que contém a função de consulta
caminho = Path("scripts/05_teste_tratamento_erros_nvd.py")

# Preparar a importação do módulo
spec = importlib.util.spec_from_file_location(
    "teste_nvd",
    caminho
)

modulo = importlib.util.module_from_spec(spec)

# Carregar o módulo sem executar a consulta de exemplo
spec.loader.exec_module(modulo)

# Simular uma resposta HTTP 503
erro_temporario = Mock()
erro_temporario.status_code = 503

# Simular uma resposta HTTP 200
resposta_sucesso = Mock()
resposta_sucesso.status_code = 200
resposta_sucesso.json.return_value = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "vulnStatus": "Analyzed"
            }
        }
    ]
}

# Substituir as requisições reais por respostas simuladas
with patch(
    "requests.get",
    side_effect=[erro_temporario, resposta_sucesso]
) as requisicao_simulada:

    # Evitar a espera de seis segundos durante o teste
    with patch("time.sleep"):

        dados = modulo.consultar_nvd(
            modulo.URL,
            modulo.parametros
        )

# Validar o resultado
cve = dados["vulnerabilities"][0]["cve"]

assert cve["id"] == "CVE-2021-44228"
assert requisicao_simulada.call_count == 2

print("\nRESULTADO DO TESTE")
print("CVE:", cve["id"])
print("Chamadas simuladas:", requisicao_simulada.call_count)
print("Teste de recuperação: OK")
