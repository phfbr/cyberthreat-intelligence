
import unittest

from cvss_selecao import selecionar_cvss_referencia


class TestarSelecaoCVSS(unittest.TestCase):

    def criar_avaliacao(
        self,
        pontuacao,
        versao,
        tipo="Secondary",
        fonte="exemplo@empresa.com"
    ):
        return {
            "source": fonte,
            "type": tipo,
            "cvssData": {
                "version": versao,
                "baseScore": pontuacao,
                "baseSeverity": "HIGH",
                "vectorString": f"TESTE-{versao}"
            }
        }

    def test_01_priorizar_cvss_40(self):

        metrics = {
            "cvssMetricV31": [
                self.criar_avaliacao(9.8, "3.1")
            ],
            "cvssMetricV40": [
                self.criar_avaliacao(6.9, "4.0")
            ]
        }

        resultado = selecionar_cvss_referencia(metrics)

        self.assertEqual(resultado["versao"], "4.0")
        self.assertEqual(resultado["pontuacao"], 6.9)

    def test_02_priorizar_primary(self):

        metrics = {
            "cvssMetricV31": [
                self.criar_avaliacao(
                    9.8, "3.1", "Secondary"
                ),
                self.criar_avaliacao(
                    5.4, "3.1", "Primary"
                )
            ]
        }

        resultado = selecionar_cvss_referencia(metrics)

        self.assertEqual(resultado["pontuacao"], 5.4)
        self.assertEqual(resultado["tipo"], "Primary")

    def test_03_priorizar_fonte_nvd(self):

        metrics = {
            "cvssMetricV31": [
                self.criar_avaliacao(
                    8.0,
                    "3.1",
                    "Secondary",
                    "outra@empresa.com"
                ),
                self.criar_avaliacao(
                    6.5,
                    "3.1",
                    "Secondary",
                    "nvd@nist.gov"
                )
            ]
        }

        resultado = selecionar_cvss_referencia(metrics)

        self.assertEqual(resultado["pontuacao"], 6.5)
        self.assertEqual(resultado["fonte"], "nvd@nist.gov")

    def test_04_ignorar_pontuacoes_invalidas(self):

        metrics = {
            "cvssMetricV40": [
                self.criar_avaliacao(-1, "4.0"),
                self.criar_avaliacao(11, "4.0"),
                self.criar_avaliacao(True, "4.0"),
                self.criar_avaliacao(
                    float("nan"), "4.0"
                )
            ],
            "cvssMetricV31": [
                self.criar_avaliacao(7.5, "3.1")
            ]
        }

        resultado = selecionar_cvss_referencia(metrics)

        self.assertEqual(resultado["versao"], "3.1")
        self.assertEqual(resultado["pontuacao"], 7.5)

    def test_05_sem_cvss_valido(self):

        resultado = selecionar_cvss_referencia({})

        self.assertIsNone(resultado)

    def test_06_independente_da_ordem(self):

        avaliacao_a = self.criar_avaliacao(
            5.0, "3.1", "Secondary", "z@empresa.com"
        )

        avaliacao_b = self.criar_avaliacao(
            7.0, "3.1", "Secondary", "a@empresa.com"
        )

        primeiro = selecionar_cvss_referencia({
            "cvssMetricV31": [
                avaliacao_a, avaliacao_b
            ]
        })

        segundo = selecionar_cvss_referencia({
            "cvssMetricV31": [
                avaliacao_b, avaliacao_a
            ]
        })

        self.assertEqual(primeiro, segundo)
        self.assertEqual(primeiro["pontuacao"], 7.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
