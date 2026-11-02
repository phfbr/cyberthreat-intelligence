
# Regra de Tratamento CPE — Versão 1.0

## Projeto
CyberThreat Intelligence | Global Security Analytics

## Fonte
NIST National Vulnerability Database (NVD)
API CVE 2.0

## Objetivo

Definir o tratamento dos identificadores CPE
associados às vulnerabilidades CVE.

## Evidências da auditoria

Período de publicação:
01/10/2026 a 07/10/2026

- CVEs analisadas: 2.743
- CVEs com CPE: 715
- CVEs sem CPE: 2.028
- Registros CPE encontrados: 8.180
- Registros com vulnerable=True: 5.002
- Registros com outros valores: 3.178

## Regra de negócio — CPE_V1

1. Preservar integralmente os dados originais
   na camada Bronze.

2. Extrair os identificadores CPE disponíveis
   nas configurações das CVEs.

3. Preservar os atributos:
   - Identificador da CVE
   - Critério CPE completo
   - Tipo de plataforma
   - Fabricante
   - Produto
   - Indicador vulnerable

4. Preservar as informações de versões e
   intervalos de versões presentes nos
   registros originais.

5. Não interpretar a ausência de CPE como
   ausência de produtos afetados.

6. Não interpretar vulnerable=True como
   evidência de exploração ou incidente.

7. Preservar a estrutura lógica das
   configurações quando necessária para
   interpretar condições AND, OR e negação.

8. Não utilizar a quantidade de registros
   CPE como quantidade de CVEs.

9. Calcular vulnerabilidades por fabricante
   utilizando CVEs distintas.

10. Não classificar fabricantes como mais
    inseguros apenas pela quantidade de
    associações encontradas.

## Modelagem analítica prevista

A camada Gold poderá conter:

- Dimensão de vulnerabilidades
- Dimensão de produtos
- Tabela de associação CVE-CPE

A modelagem definitiva dependerá da
validação dos relacionamentos e da
granularidade dos dados tratados.

## Indicadores previstos

- CVEs distintas por fabricante
- CVEs distintas por produto
- Distribuição por tipo de plataforma
- Cobertura de classificação CPE
- Severidade das CVEs associadas a produtos

## Limitações

Os dados CPE não representam instalações
comprometidas ou ataques confirmados.

A cobertura de CPE nesta coleta é parcial.

A existência de uma associação CPE não
significa necessariamente que o produto
isoladamente seja vulnerável, pois podem
existir condições adicionais de aplicabilidade.

A coleta cobre somente uma janela de
publicação de sete dias.

## Status

Regra documentada.
Implementação nas camadas Silver e Gold pendente.
