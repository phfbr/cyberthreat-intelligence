
# Regra de Seleção CVSS — Versão 1.0

## Projeto
CyberThreat Intelligence | Global Security Analytics

## Objetivo
Selecionar uma avaliação CVSS de referência por CVE,
preservando todas as avaliações originais.

## Fonte
NIST National Vulnerability Database (NVD) — API CVE 2.0.

## Critérios de seleção

1. Considerar avaliações com baseScore numérico válido,
   dentro do intervalo de 0 a 10.
2. Priorizar as versões:
   - CVSS 4.0
   - CVSS 3.1
   - CVSS 3.0
   - CVSS 2.0
3. Dentro da versão escolhida, priorizar avaliações
   identificadas como Primary.
4. Persistindo empate, priorizar a fonte nvd@nist.gov.
5. Persistindo empate, ordenar por source e vectorString.
6. Se ainda houver empate completo, usar uma ordem
   determinística dos demais atributos da avaliação.
7. Sem avaliação válida, manter pontuação e severidade nulas.

## Campos que deverão ser preservados

- Identificador CVE
- Versão CVSS selecionada
- Pontuação base
- Severidade base
- Fonte da avaliação
- Tipo da avaliação
- Vetor CVSS
- Identificação da regra aplicada

## Cuidados analíticos

- CVSS mede severidade técnica, não quantidade de ataques.
- CVSS não representa, isoladamente, risco operacional.
- Versões diferentes possuem metodologias distintas.
- A pontuação de referência é uma convenção do projeto.
- Todas as avaliações originais devem ser preservadas.
- SSVC deve ser analisado separadamente do CVSS.
- Registros sem pontuação não devem receber valor zero.

## Evidências da auditoria

Período: 01/10/2026 a 07/10/2026

- CVEs analisadas: 2.743
- CVEs com pontuação: 2.569
- CVEs sem pontuação: 174
- Avaliações CVSS: 3.372
- CVEs com múltiplas avaliações: 648
- CVEs com concorrência na mesma versão: 91


## Auditoria de impacto da prioridade de versão

A regra CVSS_REFERENCIA_V1 prioriza a versão da
avaliação antes do tipo Primary ou Secondary.

Resultados da auditoria:

- Total de CVEs analisadas: 2.743
- CVEs com avaliação Primary válida: 179
- CVEs com Primary selecionada: 97
- CVEs com Primary não selecionada: 82

As 82 ocorrências correspondem a casos em que
uma avaliação CVSS 4.0 Secondary foi selecionada
em vez de uma avaliação CVSS 3.1 Primary.

Essa escolha é uma convenção analítica do projeto
e não representa uma hierarquia oficial entre
avaliações de diferentes versões.

## Decisão metodológica

Manter provisoriamente a regra
CVSS_REFERENCIA_V1, considerando que:

1. A seleção deve ser determinística e reproduzível.
2. A versão CVSS selecionada deve ser identificada.
3. A fonte e o tipo da avaliação devem ser preservados.
4. Todas as avaliações originais devem permanecer
   disponíveis para auditoria.
5. Pontuações de versões diferentes não devem ser
   interpretadas como diretamente equivalentes.
6. A pontuação selecionada não deve ser apresentada
   como risco real de exploração ou incidente.

A decisão será reavaliada caso as análises posteriores
revelem limitações relevantes.

## Status

Regra documentada.
Implementação e testes pendentes.
