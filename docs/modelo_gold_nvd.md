# Modelo Gold — NVD

**Projeto:** CyberThreat Intelligence | Global Security Analytics  
**Fase:** 6 — Modelagem Gold  
**Status:** Proposta inicial de arquitetura

## 1. Objetivo

Construir um modelo analítico dimensional a partir das quatro tabelas Silver da NVD, preparando os dados para análises de vulnerabilidades, severidade, fraquezas de segurança, fabricantes e produtos no Power BI.

A unidade principal de análise será a vulnerabilidade identificada por seu código CVE.

## 2. Tabelas planejadas

| Tabela | Granularidade | Finalidade |
|---|---|---|
| `fato_vulnerabilidade` | Uma linha por CVE | Indicadores gerais de vulnerabilidades |
| `dim_data` | Uma linha por data | Análises temporais |
| `dim_status` | Uma linha por status NVD | Classificação do estado de análise |
| `dim_cwe` | Uma linha por código CWE | Catálogo de fraquezas |
| `ponte_cve_cwe` | Uma linha por associação CVE–CWE | Relacionar vulnerabilidades e fraquezas |
| `dim_produto` | Uma linha por combinação identificada de fabricante e produto CPE | Análises de fabricantes e produtos |
| `ponte_cve_produto` | Uma linha por associação analítica CVE–produto | Relacionar CVEs aos produtos identificados |
| `fato_avaliacao_cvss` | Uma linha por avaliação CVSS válida | Analisar versões, fontes e pontuações |

As tabelas são propostas de modelagem e ainda não foram implementadas.

## 3. Regras de negócio

### 3.1 Vulnerabilidades

- Cada CVE será contabilizada uma única vez na tabela principal.
- O identificador CVE será a chave de negócio.
- CVEs rejeitadas permanecerão identificáveis.
- CVEs rejeitadas não serão automaticamente excluídas de todas as análises.
- A pontuação CVSS de referência seguirá a regra documentada na Silver.

### 3.2 Classificações CWE

- Uma CVE pode possuir múltiplas classificações CWE.
- As associações serão preservadas na tabela ponte.
- A soma das contagens por CWE poderá ultrapassar o total de CVEs distintas.
- Indicadores de vulnerabilidades utilizarão contagem distinta de CVEs quando necessário.

### 3.3 Fabricantes e produtos CPE

- Registros CPE não representam equipamentos efetivamente comprometidos.
- Um fabricante pode possuir vários produtos.
- Uma CVE pode estar associada a múltiplos produtos.
- Ocorrências repetidas de uma combinação CVE–produto poderão ser consolidadas para análises de cobertura, preservando-se a rastreabilidade na Silver.
- Condições complexas de aplicabilidade AND/OR não serão reduzidas a afirmações de que todos os produtos listados são individualmente vulneráveis.
- A dimensão de produtos será construída a partir dos identificadores efetivamente disponíveis, sem inventar informações comerciais.

### 3.4 Avaliações CVSS

- Uma CVE pode possuir várias avaliações CVSS.
- A tabela de avaliações preservará as versões e fontes disponíveis.
- Indicadores gerais de severidade utilizarão a avaliação de referência definida anteriormente.
- Avaliações adicionais não deverão multiplicar a contagem de vulnerabilidades.

### 3.5 Datas

- As datas de publicação e atualização serão tratadas como atributos temporais distintos.
- A tabela calendário deverá contemplar os períodos presentes nos dados.
- O relacionamento ativo e os relacionamentos alternativos serão definidos antes da implementação no Power BI.

## 4. Cuidados analíticos

Não serão tratados como equivalentes:

- Vulnerabilidades publicadas e ataques realizados.
- Produtos identificados em configurações CPE e dispositivos comprometidos.
- Pontuação CVSS e probabilidade de exploração.
- País de um fabricante e origem de um ataque.
- Registros NVD e incidentes de segurança confirmados.

## 5. Critérios de validação

A modelagem Gold deverá garantir:

1. Ausência de CVEs duplicadas na tabela principal.
2. Integridade dos relacionamentos.
3. Reconciliação das contagens com a Silver.
4. Preservação das classificações múltiplas.
5. Indicadores sem multiplicação indevida de CVEs.
6. Documentação das regras de transformação e agregação.

## 6. Próximas decisões

Antes da implementação, definir:

- Chaves técnicas e de negócio.
- Colunas definitivas de cada tabela.
- Tratamento de datas e status.
- Estratégia de relacionamento das tabelas ponte no Power BI.
- Critérios de consolidação de fabricantes e produtos CPE.
- Medidas e indicadores analíticos prioritários.