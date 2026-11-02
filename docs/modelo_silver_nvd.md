
# Modelo de Dados Silver — NVD

## Projeto
CyberThreat Intelligence | Global Security Analytics

## Objetivo

Organizar os dados brutos da NVD em tabelas
tratadas, mantendo rastreabilidade e
granularidade adequada para análise.

## Tabelas planejadas

### 1. silver_cves

Granularidade: uma linha por CVE.

Campos planejados:
- cve_id
- data_publicacao
- data_modificacao
- status_nvd
- flag_rejeitada
- descricao_en
- cvss_referencia_versao
- cvss_referencia_pontuacao
- cvss_referencia_severidade
- cvss_referencia_fonte
- cvss_referencia_tipo

### 2. silver_cwe

Granularidade: uma linha por associação
única entre CVE e CWE específica.

Campos planejados:
- cve_id
- cwe_id

### 3. silver_cpe

Granularidade: uma linha por ocorrência
de CPE nas configurações da CVE.

Campos planejados:
- cve_id
- cpe_criteria
- tipo_plataforma
- fabricante
- produto
- vulnerable
- atributos_de_versao
- contexto_configuracao

Observação:
A representação de contexto_configuracao
será definida durante a implementação,
preservando as condições lógicas originais.

### 4. silver_cvss

Granularidade: uma linha por avaliação
CVSS encontrada na NVD.

Campos planejados:
- cve_id
- versao_cvss
- pontuacao
- severidade
- fonte
- tipo
- vetor
- flag_cvss_referencia

## Regras gerais

1. Não modificar os arquivos Bronze.

2. Preservar o identificador original da CVE.

3. Manter os status originais da NVD.

4. Sinalizar CVEs rejeitadas, sem apagá-las.

5. Preservar múltiplas CWEs e avaliações CVSS.

6. Não transformar ausência de informação
   em valor inventado.

7. Registrar regras de transformação
   e validação dos dados.

8. Não confundir vulnerabilidades com
   ataques ou incidentes confirmados.

## Formato de armazenamento

Formato previsto: Parquet.

Local:
data/silver/nvd/

## Status

Modelo conceitual definido.
Estrutura física e transformações pendentes
de implementação e validação.
