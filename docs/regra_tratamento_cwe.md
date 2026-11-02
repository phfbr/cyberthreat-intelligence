
# Regra de Tratamento CWE — Versão 1.0

## Projeto
CyberThreat Intelligence | Global Security Analytics

## Fonte
NIST National Vulnerability Database (NVD) — API CVE 2.0.

## Objetivo
Definir o tratamento das classificações CWE
associadas às vulnerabilidades CVE.

## Evidências da auditoria

Período: 01/10/2026 a 07/10/2026.

- Total de CVEs: 2.743
- CVEs com CWE específica: 2.516
- CVEs sem classificação CWE: 227
- CVEs com código genérico reconhecido: 0
- CVEs com múltiplas CWEs: 394

## Regra de negócio — CWE_V1

1. Preservar os dados originais na camada Bronze.

2. Extrair os códigos CWE associados a cada CVE.

3. Considerar como CWE específica os códigos
   que seguem o padrão CWE- seguido de números.

4. Remover duplicidades da combinação CVE + CWE
   na futura camada Silver.

5. Preservar todas as CWEs específicas de cada CVE,
   sem selecionar apenas a primeira.

6. Não atribuir códigos artificiais às CVEs
   sem classificação.

7. Tratar NVD-CWE-noinfo e NVD-CWE-Other como
   categorias genéricas caso apareçam em coletas
   futuras.

8. Não interpretar a presença de uma CWE como
   evidência de exploração ou incidente.

## Modelagem analítica prevista

A futura camada Gold deverá permitir um
relacionamento de muitos para muitos entre
CVEs e CWEs, utilizando uma estrutura apropriada.

Estrutura conceitual:

- Dimensão de vulnerabilidades
- Dimensão de fraquezas CWE
- Tabela de associação CVE-CWE

Uma CVE poderá estar associada a várias CWEs.

## Cuidados com os indicadores

O total de associações CVE-CWE pode superar
o total de CVEs distintas.

Indicadores de vulnerabilidades deverão utilizar
contagem distinta de identificadores CVE quando
necessário.

A soma das categorias CWE não deverá ser
interpretada automaticamente como o total
de vulnerabilidades únicas.

## Limitações

A presença de um código CWE na NVD não garante
que sua classificação esteja livre de erros.

A validade individual dos códigos no catálogo
oficial da MITRE não foi verificada nesta etapa.

## Status

Regra documentada.
Implementação na Silver e Gold pendente.
