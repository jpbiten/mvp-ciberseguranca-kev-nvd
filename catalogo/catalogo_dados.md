# Catálogo de dados

Gerado pelo notebook `02_modelagem_carga` (seção 6). Também disponível em [`catalogo_dados.csv`](catalogo_dados.csv).

Tipos: `STRING` = texto/categórico, `INT`/`DOUBLE` = numérico, `DATE` = data, `BOOLEAN` = booleano. Regras R1 a R13: ver [README](../README.md#43-regras-de-transformação).

## `stg_nvd_cve`

| Atributo | Tipo | Descrição | Domínio | Obrigatório | Linhagem |
|---|---|---|---|---|---|
| `cve_id` | STRING | Identificador da CVE | CVE-AAAA-NNNN... | Sim | NVD API 2.0: cve.id |
| `data_publicacao` | DATE | Data de publicação da CVE | 1988 em diante | Sim | NVD API 2.0: cve.published (R2) |
| `ultima_modificacao` | STRING | Data e hora da última modificação no NVD | ISO 8601 | Sim | NVD API 2.0: cve.lastModified |
| `status_nvd` | STRING | Situação da CVE no processo de análise do NVD | Analyzed, Modified, Deferred, Awaiting Analysis, Undergoing Analysis, Received, Rejected | Sim | NVD API 2.0: cve.vulnStatus |
| `versao_cvss` | STRING | Versão do CVSS da métrica escolhida | 3.1, 3.0, 4.0, 2.0; nulo se não houver | Não | NVD API 2.0: cve.metrics (R3) |
| `score_cvss` | DOUBLE | Nota base do CVSS da métrica escolhida | 0.0 a 10.0 | Não | NVD API 2.0: cve.metrics.*.cvssData.baseScore (R3) |
| `faixa_cvss` | STRING | Faixa de severidade em português | Baixa, Média, Alta, Crítica, Nenhuma, Sem CVSS | Sim | NVD API 2.0: baseSeverity ou derivada do score (R4) |
| `fonte_metrica` | STRING | Origem da métrica escolhida | Primary, Secondary; nulo se não houver | Não | NVD API 2.0: cve.metrics.*.type |
| `nvd_cisa_exploit_add` | STRING | Data de inclusão no KEV segundo o próprio NVD (usada só para conferência) | AAAA-MM-DD; nulo fora do KEV | Não | NVD API 2.0: cve.cisaExploitAdd |

## `stg_kev`

| Atributo | Tipo | Descrição | Domínio | Obrigatório | Linhagem |
|---|---|---|---|---|---|
| `cve_id` | STRING | Identificador da CVE | CVE-AAAA-NNNN... | Sim | CISA KEV: cveID |
| `fornecedor` | STRING | Fornecedor ou projeto afetado | Texto livre | Sim | CISA KEV: vendorProject (R8) |
| `produto` | STRING | Produto afetado | Texto livre | Sim | CISA KEV: product (R8) |
| `nome_vulnerabilidade` | STRING | Nome da vulnerabilidade no catálogo | Texto livre | Sim | CISA KEV: vulnerabilityName |
| `data_inclusao_kev` | DATE | Data em que a CVE entrou no KEV | 2021-11-03 em diante | Sim | CISA KEV: dateAdded (R2) |
| `prazo_correcao` | DATE | Prazo de correção exigido pela CISA | Data | Não | CISA KEV: dueDate |
| `uso_ransomware` | STRING | Uso conhecido em campanhas de ransomware | Conhecido, Desconhecido | Sim | CISA KEV: knownRansomwareCampaignUse (R7) |
| `cwes_kev` | STRING | CWEs informados pelo KEV, separados por ponto e vírgula | CWE-n; vazio se não houver | Não | CISA KEV: cwes |

## `dim_tempo`

| Atributo | Tipo | Descrição | Domínio | Obrigatório | Linhagem |
|---|---|---|---|---|---|
| `sk_data` | INT | Chave da data (AAAAMMDD) | 19880101 a fim do ano final | Sim | Gerada (R12) |
| `data` | DATE | Data | Data | Sim | Gerada |
| `ano` | INT | Ano | 1988 em diante | Sim | Derivada de data |
| `trimestre` | INT | Trimestre do ano | 1 a 4 | Sim | Derivada de data |
| `mes` | INT | Mês | 1 a 12 | Sim | Derivada de data |
| `dia` | INT | Dia do mês | 1 a 31 | Sim | Derivada de data |
| `dia_semana` | INT | Dia da semana | 1 (segunda) a 7 (domingo) | Sim | Derivada de data |

## `dim_severidade`

| Atributo | Tipo | Descrição | Domínio | Obrigatório | Linhagem |
|---|---|---|---|---|---|
| `sk_severidade` | INT | Chave da combinação versão do CVSS x faixa | Inteiro sequencial | Sim | Gerada (R12) |
| `versao_cvss` | STRING | Versão do CVSS | 3.1, 3.0, 4.0, 2.0, N/A | Sim | stg_nvd_cve.versao_cvss |
| `faixa` | STRING | Faixa de severidade | Baixa, Média, Alta, Crítica, Nenhuma, Sem CVSS | Sim | stg_nvd_cve.faixa_cvss |
| `ordem_faixa` | INT | Ordem para ordenar as faixas | 0 (Sem CVSS) a 5 (Crítica) | Sim | Definida no notebook |

## `dim_fornecedor`

| Atributo | Tipo | Descrição | Domínio | Obrigatório | Linhagem |
|---|---|---|---|---|---|
| `sk_fornecedor` | INT | Chave do par fornecedor x produto (0 = não informado) | Inteiro; 0 para CVEs fora do KEV | Sim | Gerada (R12) |
| `fornecedor` | STRING | Fornecedor ou projeto | Texto livre | Sim | stg_kev.fornecedor |
| `produto` | STRING | Produto | Texto livre | Sim | stg_kev.produto |

## `dim_cwe`

| Atributo | Tipo | Descrição | Domínio | Obrigatório | Linhagem |
|---|---|---|---|---|---|
| `cwe_id` | STRING | Identificador do tipo de falha (CWE) | CWE-n, NVD-CWE-Other, NVD-CWE-noinfo | Sim | ponte_cve_cwe.cwe_id |
| `tipo_cwe` | STRING | Específico ou genérico (categorias do NVD sem detalhe) | Específico, Genérico (NVD) | Sim | Derivada de cwe_id |
| `numero_cwe` | INT | Número do CWE; nulo nos genéricos | Inteiro | Não | Derivada de cwe_id |

## `ponte_cve_cwe`

| Atributo | Tipo | Descrição | Domínio | Obrigatório | Linhagem |
|---|---|---|---|---|---|
| `cve_id` | STRING | CVE | CVE-AAAA-NNNN... | Sim | stg_nvd_cve / stg_kev |
| `cwe_id` | STRING | CWE associado à CVE | CWE-n, NVD-CWE-Other, NVD-CWE-noinfo | Sim | NVD: weaknesses; KEV: cwes (R5) |
| `fonte_cwe` | STRING | Origem da associação | NVD, KEV | Sim | Definida no notebook (R5) |

## `fato_cve`

| Atributo | Tipo | Descrição | Domínio | Obrigatório | Linhagem |
|---|---|---|---|---|---|
| `cve_id` | STRING | Identificador da CVE (grão da fato) | CVE-AAAA-NNNN... | Sim | stg_nvd_cve |
| `sk_data_publicacao` | INT | Chave da data de publicação | FK dim_tempo | Sim | stg_nvd_cve.data_publicacao (R12) |
| `sk_data_kev` | INT | Chave da data de inclusão no KEV; nula fora do KEV | FK dim_tempo | Não | stg_kev.data_inclusao_kev (R12) |
| `sk_severidade` | INT | Chave da severidade | FK dim_severidade | Sim | R3 e R4 |
| `sk_fornecedor` | INT | Chave do fornecedor/produto; 0 fora do KEV | FK dim_fornecedor | Sim | R8 |
| `score_cvss` | DOUBLE | Nota base do CVSS | 0.0 a 10.0; nulo sem CVSS | Não | stg_nvd_cve.score_cvss |
| `status_nvd` | STRING | Situação da CVE no NVD | Ver stg_nvd_cve (sem Rejected) | Sim | stg_nvd_cve.status_nvd (R1) |
| `esta_no_kev` | BOOLEAN | Indica se a CVE consta no KEV | true, false | Sim | R6 |
| `uso_ransomware` | STRING | Uso em ransomware, ou Fora do KEV | Conhecido, Desconhecido, Fora do KEV | Sim | R6 e R7 |
| `dias_ate_kev` | INT | Dias entre a publicação e a inclusão no KEV; nulo fora do KEV | Inteiro (pode ser negativo) | Não | R9 |
| `lote_inicial_kev` | BOOLEAN | Entrou no KEV na data de criação do catálogo | true, false | Sim | R10 |
