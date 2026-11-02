
# Regra de Tratamento dos Status NVD

## Projeto
CyberThreat Intelligence | Global Security Analytics

## Fonte
NIST National Vulnerability Database (NVD) — API CVE 2.0.

## Objetivo
Definir critérios de inclusão e exclusão dos registros
CVE nos indicadores analíticos.

## Resultado da auditoria

Período de publicação: 01/10/2026 a 07/10/2026.

Total de registros CVE: 2.743.

Distribuição por status:

- Deferred: 1.342
- Analyzed: 689
- Awaiting Analysis: 442
- Received: 209
- Modified: 26
- Undergoing Analysis: 18
- Rejected: 17

## Auditoria dos registros rejeitados

Foram identificadas 17 CVEs com status Rejected.

Resultados:

- Com pontuação CVSS válida: 0
- Sem pontuação CVSS: 17
- Com referências: 0
- Sem referências: 17

As descrições incluem motivos como duplicidade,
retirada de identificadores e registros que não
representam vulnerabilidades de segurança.

## Regra de negócio — STATUS_NVD_V1

1. Preservar todos os registros originais na Bronze.

2. Preservar o status original na futura Silver.

3. Criar uma classificação analítica que permita
   distinguir registros rejeitados e não rejeitados.

4. Considerar como registros CVE não rejeitados
   aqueles cujo vulnStatus seja diferente de Rejected.

5. Excluir registros Rejected dos indicadores
   principais de vulnerabilidades não rejeitadas.

6. Manter os registros Rejected disponíveis para
   auditoria, rastreabilidade e indicadores de
   qualidade dos dados.

7. Não excluir automaticamente registros Deferred,
   Received, Awaiting Analysis, Undergoing Analysis,
   Modified ou Analyzed.

8. Não interpretar o status NVD como evidência de
   exploração, ataque ou incidente confirmado.

## Indicadores de referência

- Registros CVE coletados: 2.743
- Registros CVE não rejeitados: 2.726
- Registros CVE rejeitados: 17

Essas quantidades representam o estado dos dados
na coleta auditada e não devem ser tratadas como
valores permanentes.

## Observações metodológicas

O status de uma CVE pode mudar após a coleta.

A classificação deverá ser recalculada quando
novos dados forem obtidos.

O universo de CVEs não rejeitadas não representa
necessariamente o universo de vulnerabilidades
exploradas ou de incidentes confirmados.

## Status da implementação

Regra documentada.
Implementação na Silver pendente.
