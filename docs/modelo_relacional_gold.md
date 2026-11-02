# Modelo Relacional Gold — NVD

**Projeto:** CyberThreat Intelligence | Global Security Analytics  
**Fonte:** NIST National Vulnerability Database (NVD)  
**Período de publicação da coleta:** 01/10/2026 a 07/10/2026 (UTC)

## 1. Objetivo

Disponibilizar um modelo analítico para estudar vulnerabilidades registradas na NVD, suas classificações, avaliações CVSS e associações com produtos e plataformas.

O modelo não representa ataques realizados, incidentes confirmados ou quantidades de dispositivos efetivamente comprometidos.

## 2. Tabelas e granularidade

| Tabela | Granularidade | Chave |
|---|---|---|
| fato_vulnerabilidade | Uma linha por CVE | cve_id |
| dim_status | Uma linha por status NVD | status_id |
| dim_data | Uma linha por dia UTC | data_id |
| dim_cwe | Uma linha por código CWE | cwe_id |
| ponte_cve_cwe | Uma linha por associação CVE–CWE | cve_id + cwe_id |
| dim_produto | Uma linha por fabricante–produto | produto_id |
| ponte_cve_produto | Uma linha por associação CVE–produto | cve_id + produto_id |
| fato_avaliacao_cvss | Uma linha por avaliação CVSS | avaliacao_cvss_id |

## 3. Relacionamentos previstos

- dim_status[status_id] (1) → fato_vulnerabilidade[status_id] (*)
- dim_data[data_id] (1) → fato_vulnerabilidade[data_publicacao_id] (*) — relacionamento temporal principal
- dim_data[data_id] (1) → fato_vulnerabilidade[data_atualizacao_id] (*) — relacionamento temporal alternativo
- fato_vulnerabilidade[cve_id] (1) → ponte_cve_cwe[cve_id] (*)
- dim_cwe[cwe_id] (1) → ponte_cve_cwe[cwe_id] (*)
- fato_vulnerabilidade[cve_id] (1) → ponte_cve_produto[cve_id] (*)
- dim_produto[produto_id] (1) → ponte_cve_produto[produto_id] (*)
- fato_vulnerabilidade[cve_id] (1) → fato_avaliacao_cvss[cve_id] (*)

As relações entre dimensões e tabelas ponte deverão ser configuradas cuidadosamente no Power BI. O uso de filtros bidirecionais não será adotado automaticamente; a propagação dos filtros será testada com medidas específicas.

## 4. Regras analíticas

1. A contagem principal de vulnerabilidades deve utilizar CVEs distintas, não a soma de linhas das tabelas ponte.
2. A análise temporal principal utiliza a data de publicação.
3. A data de atualização é uma perspectiva temporal alternativa.
4. A análise geral de severidade utiliza o CVSS de referência selecionado no pipeline.
5. As avaliações CVSS adicionais permanecem disponíveis para análises específicas.
6. Os códigos CWE representam categorias de fraquezas associadas às CVEs.
7. As associações CPE representam critérios de plataformas e produtos registrados na NVD; não comprovam exposição real de equipamentos.
8. As condições completas de aplicabilidade CPE, incluindo operadores lógicos, não são integralmente reconstruídas pela ponte analítica.
9. Os status NVD representam estados do processamento dos registros, não a situação de exploração ativa de cada vulnerabilidade.

## 5. Indicadores de referência

| Indicador | Valor validado |
|---|---:|
| CVEs únicas | 2.743 |
| CVEs com CVSS | 2.569 |
| CVEs com CWE | 2.516 |
| CVEs com CPE | 715 |
| CVEs rejeitadas | 17 |
| Avaliações CVSS | 3.372 |
| Associações CVE–CWE | 2.968 |
| Associações CVE–produto | 6.968 |

## 6. Validação

A auditoria consolidada foi executada pelo script `scripts/67_validar_gold_consolidada.py`.

Resultado: `Auditoria Consolidada Gold: OK`.

Todos os oito relacionamentos testados apresentaram zero chaves inválidas.

## 7. Próxima etapa

Importar as oito tabelas Parquet no Power BI, configurar os relacionamentos e validar medidas DAX antes da construção dos dashboards.