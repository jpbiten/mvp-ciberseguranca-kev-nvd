# Databricks notebook source
# MAGIC %md
# MAGIC # 02 - Modelagem e carga (ETL): esquema estrela
# MAGIC
# MAGIC **MVP - Segurança cibernética** | Universidade de Brasília - Engenharia de Produção
# MAGIC **Autor:** João Pedro Ferreira Bitencourt (matrícula 211068047)
# MAGIC
# MAGIC Este notebook lê os dados brutos coletados no notebook 01 (Volume `raw`), aplica as regras de transformação abaixo e grava as tabelas do modelo dimensional (Delta, Unity Catalog).
# MAGIC
# MAGIC > This product uses the NVD API but is not endorsed or certified by the NVD.
# MAGIC
# MAGIC ## Modelo (esquema estrela)
# MAGIC
# MAGIC ```
# MAGIC   dim_tempo (publicação)     dim_tempo (inclusão no KEV)
# MAGIC              \                    /
# MAGIC               \                  /
# MAGIC   dim_severidade ---- fato_cve ---- dim_fornecedor
# MAGIC                          |
# MAGIC                    ponte_cve_cwe ---- dim_cwe
# MAGIC ```
# MAGIC
# MAGIC - **Grão da fato:** uma linha por CVE (exceto rejeitadas).
# MAGIC - **dim_tempo** é usada duas vezes (data de publicação e data de inclusão no KEV).
# MAGIC - **ponte_cve_cwe:** uma CVE pode ter vários CWEs, então a relação é N:N.
# MAGIC - Camada intermediária: `stg_nvd_cve` e `stg_kev` (dados extraídos, ainda sem modelagem).
# MAGIC
# MAGIC ## Regras de transformação
# MAGIC
# MAGIC | # | Regra |
# MAGIC |---|---|
# MAGIC | R1 | **Universo:** CVEs com status `Rejected` ficam em `stg_nvd_cve` (com o status), mas **não entram** na fato. |
# MAGIC | R2 | **Datas:** `published` (NVD) e `dateAdded` (KEV) viram `DATE` (só a parte da data, em UTC). |
# MAGIC | R3 | **CVSS:** escolhe-se uma métrica por CVE, na ordem v3.1 > v3.0 > v4.0 > v2.0. Dentro da versão, prefere-se a fonte `Primary` (NVD). Sem métrica: faixa `Sem CVSS`. |
# MAGIC | R4 | **Faixa de severidade:** usa-se `baseSeverity` da fonte; se faltar, deriva-se do score pela escala da própria versão. Rótulos em português. A versão do CVSS é preservada porque as escalas não são comparáveis (a v2.0 não tem faixa Crítica). |
# MAGIC | R5 | **CWE:** extraído de `weaknesses` do NVD (inclui `NVD-CWE-Other` e `NVD-CWE-noinfo`, tratados como genéricos). Se o NVD não trouxer CWE e o KEV trouxer, usa-se o do KEV (`fonte_cwe = KEV`). |
# MAGIC | R6 | **Cruzamento NVD x KEV:** por `cve_id`, partindo do NVD (left join). CVE ausente do KEV recebe `esta_no_kev = false` e `uso_ransomware = Fora do KEV`. |
# MAGIC | R7 | **Uso em ransomware:** `Known` vira `Conhecido`; `Unknown` vira `Desconhecido`. **Desconhecido não significa que não foi usado.** |
# MAGIC | R8 | **Fornecedor/produto:** vêm só do KEV (`vendorProject`, `product`), sem espaços nas pontas. CVE fora do KEV recebe a chave 0 (`Não informado`). |
# MAGIC | R9 | **Dias até o KEV:** `data_inclusao_kev - data_publicacao`, só para CVEs do KEV. Valores negativos são mantidos e contados no controle de qualidade. |
# MAGIC | R10 | **Lote inicial do KEV:** inclusões na data de criação do catálogo (a mais antiga) recebem `lote_inicial_kev = true`, pois medem estoque antigo, e não tempo de reação. |
# MAGIC | R11 | **Duplicatas:** por `cve_id`, mantém-se o registro com maior `lastModified`. |
# MAGIC | R12 | **Chaves:** `sk_data = AAAAMMDD`; `sk_severidade` e `sk_fornecedor` são sequenciais. |
# MAGIC | R13 | **Idempotência:** as tabelas são sobrescritas a cada execução. |

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1. Configuração

# COMMAND ----------

import gzip
import json
import os
from datetime import date

import pandas as pd

CATALOG = "workspace"
SCHEMA = "mvp_ciber"
BASE = f"/Volumes/{CATALOG}/{SCHEMA}/raw"
DESTINO = f"{CATALOG}.{SCHEMA}"

ORDEM_METRICAS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")
VERSAO_PADRAO = {"cvssMetricV31": "3.1", "cvssMetricV30": "3.0", "cvssMetricV40": "4.0", "cvssMetricV2": "2.0"}
FAIXA_PT = {"NONE": "Nenhuma", "LOW": "Baixa", "MEDIUM": "Média", "HIGH": "Alta", "CRITICAL": "Crítica"}
ORDEM_FAIXA = {"Sem CVSS": 0, "Nenhuma": 1, "Baixa": 2, "Média": 3, "Alta": 4, "Crítica": 5}
USO_RANSOMWARE_PT = {"Known": "Conhecido", "Unknown": "Desconhecido"}

print("Origem:", BASE)
print("Destino:", DESTINO)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. Extração (dados brutos para tabelas de estágio)

# COMMAND ----------


def faixa_por_score(score: float, versao: str) -> str:
    """R4 (contingência): deriva a faixa em inglês a partir do score, pela escala da versão."""
    if versao == "2.0":
        return "LOW" if score < 4.0 else "MEDIUM" if score < 7.0 else "HIGH"
    if score == 0:
        return "NONE"
    return "LOW" if score < 4.0 else "MEDIUM" if score < 7.0 else "HIGH" if score < 9.0 else "CRITICAL"


def escolher_metrica(metrics: dict):
    """R3 e R4: devolve (versao, score, faixa_pt, tipo_fonte) da melhor métrica disponível."""
    for chave in ORDEM_METRICAS:
        lista = metrics.get(chave) or []
        if not lista:
            continue
        item = next((x for x in lista if x.get("type") == "Primary"), lista[0])
        dados = item.get("cvssData", {})
        score = dados.get("baseScore")
        if score is None:
            continue  # métrica inválida: tenta a próxima versão
        versao = str(dados.get("version") or VERSAO_PADRAO[chave])
        sev = (dados.get("baseSeverity") or item.get("baseSeverity") or "").upper()
        if sev not in FAIXA_PT:
            sev = faixa_por_score(float(score), versao)
        return versao, float(score), FAIXA_PT[sev], item.get("type")
    return None, None, "Sem CVSS", None


def chave_data(serie: pd.Series) -> pd.Series:
    """R12: converte datas em chave inteira AAAAMMDD (nula quando a data é nula)."""
    return (serie.dt.year * 10000 + serie.dt.month * 100 + serie.dt.day).astype("Int64")


def extrair_cwes(cve: dict) -> list:
    """R5: lista única de identificadores de CWE de uma CVE, na ordem em que aparecem."""
    vistos = []
    for w in cve.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            valor = (d.get("value") or "").strip()
            if valor and valor not in vistos:
                vistos.append(valor)
    return vistos


def extrair_nvd():
    arquivos = sorted(f for f in os.listdir(f"{BASE}/nvd") if f.endswith(".json.gz"))
    linhas, cwes = [], []
    for nome in arquivos:
        with gzip.open(f"{BASE}/nvd/{nome}", "rb") as f:
            pagina = json.loads(f.read())
        for item in pagina["vulnerabilities"]:
            c = item["cve"]
            versao, score, faixa, tipo_fonte = escolher_metrica(c.get("metrics", {}))
            linhas.append({
                "cve_id": c["id"].strip(),
                "data_publicacao": c["published"][:10],
                "ultima_modificacao": c.get("lastModified", c["published"]),
                "status_nvd": c.get("vulnStatus", "Desconhecido"),
                "versao_cvss": versao,
                "score_cvss": score,
                "faixa_cvss": faixa,
                "fonte_metrica": tipo_fonte,
                "nvd_cisa_exploit_add": c.get("cisaExploitAdd"),
            })
            for cwe in extrair_cwes(c):
                cwes.append({"cve_id": c["id"].strip(), "cwe_id": cwe, "fonte_cwe": "NVD"})
    return pd.DataFrame(linhas), pd.DataFrame(cwes), len(arquivos)


def extrair_kev():
    pasta = f"{BASE}/kev"
    arquivo = sorted(f for f in os.listdir(pasta) if f.endswith(".json"))[-1]
    with open(f"{pasta}/{arquivo}", encoding="utf-8") as f:
        dados = json.load(f)
    linhas = []
    for v in dados["vulnerabilities"]:
        linhas.append({
            "cve_id": v["cveID"].strip(),
            "fornecedor": (v.get("vendorProject") or "").strip(),
            "produto": (v.get("product") or "").strip(),
            "nome_vulnerabilidade": (v.get("vulnerabilityName") or "").strip(),
            "data_inclusao_kev": v["dateAdded"],
            "prazo_correcao": v.get("dueDate"),
            "uso_ransomware": USO_RANSOMWARE_PT.get(v.get("knownRansomwareCampaignUse"), "Desconhecido"),
            "cwes_kev": ";".join(v.get("cwes") or []),
        })
    return pd.DataFrame(linhas), arquivo, dados.get("catalogVersion")


stg_nvd, stg_cwe_nvd, n_paginas = extrair_nvd()
stg_kev, arquivo_kev, versao_kev = extrair_kev()

# R11: duplicatas por cve_id (mantém a de maior última modificação)
antes = len(stg_nvd)
stg_nvd = stg_nvd.sort_values("ultima_modificacao").drop_duplicates("cve_id", keep="last").reset_index(drop=True)
print(f"Páginas lidas: {n_paginas} | CVEs no NVD: {len(stg_nvd)} (duplicatas removidas: {antes - len(stg_nvd)})")
print(f"KEV: {len(stg_kev)} registros (arquivo {arquivo_kev}, catálogo {versao_kev})")

# R2: datas como data
stg_nvd["data_publicacao"] = pd.to_datetime(stg_nvd["data_publicacao"])
stg_kev["data_inclusao_kev"] = pd.to_datetime(stg_kev["data_inclusao_kev"])
stg_kev["prazo_correcao"] = pd.to_datetime(stg_kev["prazo_correcao"], errors="coerce")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. Transformação (dimensões e fato)

# COMMAND ----------

# R1: universo da análise
nvd = stg_nvd[stg_nvd["status_nvd"] != "Rejected"].copy()
print(f"R1: {len(stg_nvd) - len(nvd)} CVEs rejeitadas fora da fato; universo = {len(nvd)}")

# --- dim_tempo ---
inicio = min(nvd["data_publicacao"].min(), stg_kev["data_inclusao_kev"].min())
fim = max(nvd["data_publicacao"].max(), stg_kev["data_inclusao_kev"].max())
datas = pd.date_range(inicio.replace(month=1, day=1), fim.replace(month=12, day=31), freq="D")
dim_tempo = pd.DataFrame({"data": datas})
dim_tempo["sk_data"] = chave_data(dim_tempo["data"]).astype("int64")
dim_tempo["ano"] = dim_tempo["data"].dt.year
dim_tempo["trimestre"] = dim_tempo["data"].dt.quarter
dim_tempo["mes"] = dim_tempo["data"].dt.month
dim_tempo["dia"] = dim_tempo["data"].dt.day
dim_tempo["dia_semana"] = dim_tempo["data"].dt.dayofweek + 1  # 1 = segunda ... 7 = domingo
dim_tempo = dim_tempo[["sk_data", "data", "ano", "trimestre", "mes", "dia", "dia_semana"]]

# --- dim_severidade ---
combos = nvd[["versao_cvss", "faixa_cvss"]].fillna({"versao_cvss": "N/A"}).drop_duplicates()
combos = combos.assign(ordem_faixa=combos["faixa_cvss"].map(ORDEM_FAIXA)).sort_values(["versao_cvss", "ordem_faixa"])
dim_severidade = combos.reset_index(drop=True)
dim_severidade.insert(0, "sk_severidade", range(1, len(dim_severidade) + 1))
dim_severidade = dim_severidade.rename(columns={"faixa_cvss": "faixa"})

# --- dim_fornecedor (R8: só o KEV informa fornecedor/produto) ---
forn = stg_kev[["fornecedor", "produto"]].drop_duplicates().sort_values(["fornecedor", "produto"]).reset_index(drop=True)
forn.insert(0, "sk_fornecedor", range(1, len(forn) + 1))
dim_fornecedor = pd.concat(
    [pd.DataFrame([{"sk_fornecedor": 0, "fornecedor": "Não informado", "produto": "Não informado"}]), forn],
    ignore_index=True,
)

# --- CWE (R5): NVD, com complemento do KEV quando o NVD não traz nenhum ---
cwe_kev = stg_kev[["cve_id", "cwes_kev"]].assign(cwe_id=lambda d: d["cwes_kev"].str.split(";")).explode("cwe_id")
cwe_kev = cwe_kev[cwe_kev["cwe_id"].fillna("").str.strip() != ""][["cve_id", "cwe_id"]].assign(fonte_cwe="KEV")
cves_com_cwe_nvd = set(stg_cwe_nvd["cve_id"])
cwe_kev = cwe_kev[~cwe_kev["cve_id"].isin(cves_com_cwe_nvd)]
ponte = pd.concat([stg_cwe_nvd, cwe_kev], ignore_index=True).drop_duplicates(["cve_id", "cwe_id"])
ponte = ponte[ponte["cve_id"].isin(nvd["cve_id"])].reset_index(drop=True)  # só CVEs da fato (R1)
ponte_cve_cwe = ponte[["cve_id", "cwe_id", "fonte_cwe"]]

dim_cwe = pd.DataFrame({"cwe_id": sorted(ponte_cve_cwe["cwe_id"].unique())})
dim_cwe["tipo_cwe"] = dim_cwe["cwe_id"].apply(lambda x: "Genérico (NVD)" if x.startswith("NVD-CWE") else "Específico")
dim_cwe["numero_cwe"] = pd.to_numeric(dim_cwe["cwe_id"].str.extract(r"^CWE-(\d+)$")[0], errors="coerce").astype("Int64")

# --- fato_cve (R6 a R10) ---
kev_base = stg_kev.drop_duplicates("cve_id", keep="last")
f = nvd.merge(kev_base, on="cve_id", how="left")
f["esta_no_kev"] = f["data_inclusao_kev"].notna()
f["uso_ransomware"] = f["uso_ransomware"].fillna("Fora do KEV")
f["dias_ate_kev"] = (f["data_inclusao_kev"] - f["data_publicacao"]).dt.days.astype("Int64")  # R9
data_criacao_kev = stg_kev["data_inclusao_kev"].min()
f["lote_inicial_kev"] = f["esta_no_kev"] & (f["data_inclusao_kev"] == data_criacao_kev)  # R10
f["sk_data_publicacao"] = chave_data(f["data_publicacao"]).astype("int64")
f["sk_data_kev"] = chave_data(f["data_inclusao_kev"])
f["versao_cvss"] = f["versao_cvss"].fillna("N/A")
f = f.merge(dim_severidade[["sk_severidade", "versao_cvss", "faixa"]],
            left_on=["versao_cvss", "faixa_cvss"], right_on=["versao_cvss", "faixa"], how="left")
f = f.merge(dim_fornecedor, on=["fornecedor", "produto"], how="left")
f["sk_fornecedor"] = f["sk_fornecedor"].fillna(0).astype(int)

fato_cve = f[[
    "cve_id", "sk_data_publicacao", "sk_data_kev", "sk_severidade", "sk_fornecedor",
    "score_cvss", "status_nvd", "esta_no_kev", "uso_ransomware", "dias_ate_kev", "lote_inicial_kev",
]].reset_index(drop=True)

print(f"fato_cve: {len(fato_cve)} linhas | dim_tempo: {len(dim_tempo)} | dim_severidade: {len(dim_severidade)} | "
      f"dim_fornecedor: {len(dim_fornecedor)} | dim_cwe: {len(dim_cwe)} | ponte_cve_cwe: {len(ponte_cve_cwe)}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4. Controle de qualidade antes da carga

# COMMAND ----------

qa = []


def registrar(teste, resultado, esperado=""):
    qa.append({"teste": teste, "resultado": str(resultado), "esperado": str(esperado)})


registrar("CVEs únicas na fato", bool(fato_cve["cve_id"].is_unique), "True")
registrar("CVEs do KEV encontradas na fato", int(fato_cve["esta_no_kev"].sum()), f"{len(kev_base)} (total do KEV)")
sem_par = sorted(set(kev_base["cve_id"]) - set(fato_cve["cve_id"]))
registrar("CVEs do KEV sem correspondência no NVD (ou rejeitadas)", len(sem_par), "0")
registrar("sk_severidade nula na fato", int(fato_cve["sk_severidade"].isna().sum()), "0")
registrar("sk_data_publicacao fora da dim_tempo", int((~fato_cve["sk_data_publicacao"].isin(dim_tempo["sk_data"])).sum()), "0")
kev_fato = fato_cve[fato_cve["esta_no_kev"]]
registrar("sk_data_kev fora da dim_tempo", int((~kev_fato["sk_data_kev"].isin(dim_tempo["sk_data"])).sum()), "0")
registrar("dias_ate_kev negativos (mantidos, R9)", int((kev_fato["dias_ate_kev"] < 0).sum()), "informativo")
registrar("CVEs da fato sem nenhuma métrica CVSS", f"{int((fato_cve['sk_severidade'].map(dim_severidade.set_index('sk_severidade')['faixa']) == 'Sem CVSS').sum())}", "informativo")
registrar("CVEs da fato sem nenhum CWE", int((~fato_cve["cve_id"].isin(ponte_cve_cwe["cve_id"])).sum()), "informativo")
concorda = f.loc[f["esta_no_kev"] & f["nvd_cisa_exploit_add"].notna()]
if len(concorda):
    iguais = (concorda["nvd_cisa_exploit_add"].astype(str).str[:10] == concorda["data_inclusao_kev"].dt.strftime("%Y-%m-%d")).mean()
    registrar("Data de inclusão no KEV: coincidência KEV x NVD (%)", round(100 * float(iguais), 1), "~100")
print("Lote inicial do KEV:", data_criacao_kev.date(), "->", int(fato_cve["lote_inicial_kev"].sum()), "CVEs")
if sem_par:
    print("ATENÇÃO - CVEs do KEV sem par no NVD:", sem_par[:20])
display(pd.DataFrame(qa)) if "display" in globals() else print(pd.DataFrame(qa).to_string())

# COMMAND ----------

# MAGIC %md
# MAGIC ## 5. Carga (tabelas Delta no Unity Catalog)

# COMMAND ----------

TABELAS = {
    "stg_nvd_cve": (stg_nvd, "cve_id STRING, data_publicacao DATE, ultima_modificacao STRING, status_nvd STRING, "
                             "versao_cvss STRING, score_cvss DOUBLE, faixa_cvss STRING, fonte_metrica STRING, "
                             "nvd_cisa_exploit_add STRING"),
    "stg_kev": (stg_kev, "cve_id STRING, fornecedor STRING, produto STRING, nome_vulnerabilidade STRING, "
                         "data_inclusao_kev DATE, prazo_correcao DATE, uso_ransomware STRING, cwes_kev STRING"),
    "dim_tempo": (dim_tempo, "sk_data INT, data DATE, ano INT, trimestre INT, mes INT, dia INT, dia_semana INT"),
    "dim_severidade": (dim_severidade, "sk_severidade INT, versao_cvss STRING, faixa STRING, ordem_faixa INT"),
    "dim_fornecedor": (dim_fornecedor, "sk_fornecedor INT, fornecedor STRING, produto STRING"),
    "dim_cwe": (dim_cwe, "cwe_id STRING, tipo_cwe STRING, numero_cwe INT"),
    "ponte_cve_cwe": (ponte_cve_cwe, "cve_id STRING, cwe_id STRING, fonte_cwe STRING"),
    "fato_cve": (fato_cve, "cve_id STRING, sk_data_publicacao INT, sk_data_kev INT, sk_severidade INT, "
                           "sk_fornecedor INT, score_cvss DOUBLE, status_nvd STRING, esta_no_kev BOOLEAN, "
                           "uso_ransomware STRING, dias_ate_kev INT, lote_inicial_kev BOOLEAN"),
}


def preparar(pdf: pd.DataFrame, ddl: str) -> pd.DataFrame:
    """Converte para tipos aceitos pelo Spark: datas em date, nulos em None."""
    colunas = [c.strip().split(" ")[0] for c in ddl.split(",")]
    saida = pdf[colunas].copy()
    for c in saida.columns:
        if pd.api.types.is_datetime64_any_dtype(saida[c]):
            saida[c] = saida[c].dt.date
    return saida.astype(object).where(saida.notna(), None)


def salvar(nome: str, pdf: pd.DataFrame, ddl: str):
    sdf = spark.createDataFrame(preparar(pdf, ddl), schema=ddl)
    (sdf.write.mode("overwrite").option("overwriteSchema", "true").saveAsTable(f"{DESTINO}.{nome}"))
    print(f"{DESTINO}.{nome}: {sdf.count()} linhas")


for nome, (pdf, ddl) in TABELAS.items():
    salvar(nome, pdf, ddl)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 6. Catálogo de dados (nome, tipo, descrição, domínio, obrigatoriedade, linhagem)

# COMMAND ----------

NVD_ORIGEM = "NVD API 2.0"
CATALOGO = [
    # tabela, coluna, tipo, descricao, dominio, obrigatoria, linhagem
    ("stg_nvd_cve", "cve_id", "STRING", "Identificador da CVE", "CVE-AAAA-NNNN...", "Sim", f"{NVD_ORIGEM}: cve.id"),
    ("stg_nvd_cve", "data_publicacao", "DATE", "Data de publicação da CVE", "1988 em diante", "Sim", f"{NVD_ORIGEM}: cve.published (R2)"),
    ("stg_nvd_cve", "ultima_modificacao", "STRING", "Data e hora da última modificação no NVD", "ISO 8601", "Sim", f"{NVD_ORIGEM}: cve.lastModified"),
    ("stg_nvd_cve", "status_nvd", "STRING", "Situação da CVE no processo de análise do NVD", "Analyzed, Modified, Deferred, Awaiting Analysis, Undergoing Analysis, Received, Rejected", "Sim", f"{NVD_ORIGEM}: cve.vulnStatus"),
    ("stg_nvd_cve", "versao_cvss", "STRING", "Versão do CVSS da métrica escolhida", "3.1, 3.0, 4.0, 2.0; nulo se não houver", "Não", f"{NVD_ORIGEM}: cve.metrics (R3)"),
    ("stg_nvd_cve", "score_cvss", "DOUBLE", "Nota base do CVSS da métrica escolhida", "0.0 a 10.0", "Não", f"{NVD_ORIGEM}: cve.metrics.*.cvssData.baseScore (R3)"),
    ("stg_nvd_cve", "faixa_cvss", "STRING", "Faixa de severidade em português", "Baixa, Média, Alta, Crítica, Nenhuma, Sem CVSS", "Sim", f"{NVD_ORIGEM}: baseSeverity ou derivada do score (R4)"),
    ("stg_nvd_cve", "fonte_metrica", "STRING", "Origem da métrica escolhida", "Primary, Secondary; nulo se não houver", "Não", f"{NVD_ORIGEM}: cve.metrics.*.type"),
    ("stg_nvd_cve", "nvd_cisa_exploit_add", "STRING", "Data de inclusão no KEV segundo o próprio NVD (usada só para conferência)", "AAAA-MM-DD; nulo fora do KEV", "Não", f"{NVD_ORIGEM}: cve.cisaExploitAdd"),
    ("stg_kev", "cve_id", "STRING", "Identificador da CVE", "CVE-AAAA-NNNN...", "Sim", "CISA KEV: cveID"),
    ("stg_kev", "fornecedor", "STRING", "Fornecedor ou projeto afetado", "Texto livre", "Sim", "CISA KEV: vendorProject (R8)"),
    ("stg_kev", "produto", "STRING", "Produto afetado", "Texto livre", "Sim", "CISA KEV: product (R8)"),
    ("stg_kev", "nome_vulnerabilidade", "STRING", "Nome da vulnerabilidade no catálogo", "Texto livre", "Sim", "CISA KEV: vulnerabilityName"),
    ("stg_kev", "data_inclusao_kev", "DATE", "Data em que a CVE entrou no KEV", "2021-11-03 em diante", "Sim", "CISA KEV: dateAdded (R2)"),
    ("stg_kev", "prazo_correcao", "DATE", "Prazo de correção exigido pela CISA", "Data", "Não", "CISA KEV: dueDate"),
    ("stg_kev", "uso_ransomware", "STRING", "Uso conhecido em campanhas de ransomware", "Conhecido, Desconhecido", "Sim", "CISA KEV: knownRansomwareCampaignUse (R7)"),
    ("stg_kev", "cwes_kev", "STRING", "CWEs informados pelo KEV, separados por ponto e vírgula", "CWE-n; vazio se não houver", "Não", "CISA KEV: cwes"),
    ("dim_tempo", "sk_data", "INT", "Chave da data (AAAAMMDD)", "19880101 a fim do ano final", "Sim", "Gerada (R12)"),
    ("dim_tempo", "data", "DATE", "Data", "Data", "Sim", "Gerada"),
    ("dim_tempo", "ano", "INT", "Ano", "1988 em diante", "Sim", "Derivada de data"),
    ("dim_tempo", "trimestre", "INT", "Trimestre do ano", "1 a 4", "Sim", "Derivada de data"),
    ("dim_tempo", "mes", "INT", "Mês", "1 a 12", "Sim", "Derivada de data"),
    ("dim_tempo", "dia", "INT", "Dia do mês", "1 a 31", "Sim", "Derivada de data"),
    ("dim_tempo", "dia_semana", "INT", "Dia da semana", "1 (segunda) a 7 (domingo)", "Sim", "Derivada de data"),
    ("dim_severidade", "sk_severidade", "INT", "Chave da combinação versão do CVSS x faixa", "Inteiro sequencial", "Sim", "Gerada (R12)"),
    ("dim_severidade", "versao_cvss", "STRING", "Versão do CVSS", "3.1, 3.0, 4.0, 2.0, N/A", "Sim", "stg_nvd_cve.versao_cvss"),
    ("dim_severidade", "faixa", "STRING", "Faixa de severidade", "Baixa, Média, Alta, Crítica, Nenhuma, Sem CVSS", "Sim", "stg_nvd_cve.faixa_cvss"),
    ("dim_severidade", "ordem_faixa", "INT", "Ordem para ordenar as faixas", "0 (Sem CVSS) a 5 (Crítica)", "Sim", "Definida no notebook"),
    ("dim_fornecedor", "sk_fornecedor", "INT", "Chave do par fornecedor x produto (0 = não informado)", "Inteiro; 0 para CVEs fora do KEV", "Sim", "Gerada (R12)"),
    ("dim_fornecedor", "fornecedor", "STRING", "Fornecedor ou projeto", "Texto livre", "Sim", "stg_kev.fornecedor"),
    ("dim_fornecedor", "produto", "STRING", "Produto", "Texto livre", "Sim", "stg_kev.produto"),
    ("dim_cwe", "cwe_id", "STRING", "Identificador do tipo de falha (CWE)", "CWE-n, NVD-CWE-Other, NVD-CWE-noinfo", "Sim", "ponte_cve_cwe.cwe_id"),
    ("dim_cwe", "tipo_cwe", "STRING", "Específico ou genérico (categorias do NVD sem detalhe)", "Específico, Genérico (NVD)", "Sim", "Derivada de cwe_id"),
    ("dim_cwe", "numero_cwe", "INT", "Número do CWE; nulo nos genéricos", "Inteiro", "Não", "Derivada de cwe_id"),
    ("ponte_cve_cwe", "cve_id", "STRING", "CVE", "CVE-AAAA-NNNN...", "Sim", "stg_nvd_cve / stg_kev"),
    ("ponte_cve_cwe", "cwe_id", "STRING", "CWE associado à CVE", "CWE-n, NVD-CWE-Other, NVD-CWE-noinfo", "Sim", "NVD: weaknesses; KEV: cwes (R5)"),
    ("ponte_cve_cwe", "fonte_cwe", "STRING", "Origem da associação", "NVD, KEV", "Sim", "Definida no notebook (R5)"),
    ("fato_cve", "cve_id", "STRING", "Identificador da CVE (grão da fato)", "CVE-AAAA-NNNN...", "Sim", "stg_nvd_cve"),
    ("fato_cve", "sk_data_publicacao", "INT", "Chave da data de publicação", "FK dim_tempo", "Sim", "stg_nvd_cve.data_publicacao (R12)"),
    ("fato_cve", "sk_data_kev", "INT", "Chave da data de inclusão no KEV; nula fora do KEV", "FK dim_tempo", "Não", "stg_kev.data_inclusao_kev (R12)"),
    ("fato_cve", "sk_severidade", "INT", "Chave da severidade", "FK dim_severidade", "Sim", "R3 e R4"),
    ("fato_cve", "sk_fornecedor", "INT", "Chave do fornecedor/produto; 0 fora do KEV", "FK dim_fornecedor", "Sim", "R8"),
    ("fato_cve", "score_cvss", "DOUBLE", "Nota base do CVSS", "0.0 a 10.0; nulo sem CVSS", "Não", "stg_nvd_cve.score_cvss"),
    ("fato_cve", "status_nvd", "STRING", "Situação da CVE no NVD", "Ver stg_nvd_cve (sem Rejected)", "Sim", "stg_nvd_cve.status_nvd (R1)"),
    ("fato_cve", "esta_no_kev", "BOOLEAN", "Indica se a CVE consta no KEV", "true, false", "Sim", "R6"),
    ("fato_cve", "uso_ransomware", "STRING", "Uso em ransomware, ou Fora do KEV", "Conhecido, Desconhecido, Fora do KEV", "Sim", "R6 e R7"),
    ("fato_cve", "dias_ate_kev", "INT", "Dias entre a publicação e a inclusão no KEV; nulo fora do KEV", "Inteiro (pode ser negativo)", "Não", "R9"),
    ("fato_cve", "lote_inicial_kev", "BOOLEAN", "Entrou no KEV na data de criação do catálogo", "true, false", "Sim", "R10"),
]
catalogo = pd.DataFrame(CATALOGO, columns=["tabela", "coluna", "tipo", "descricao", "dominio", "obrigatoria", "linhagem"])

# Conferência: todo campo de todas as tabelas precisa estar no catálogo, e só eles
esperado = {(t, c.strip().split(" ")[0]) for t, (_, ddl) in TABELAS.items() for c in ddl.split(",")}
documentado = set(zip(catalogo["tabela"], catalogo["coluna"]))
assert esperado == documentado, f"Catálogo diverge das tabelas. Faltam: {esperado - documentado} | Sobram: {documentado - esperado}"
print(f"Catálogo completo: {len(catalogo)} campos em {catalogo['tabela'].nunique()} tabelas.")

# COMMAND ----------

def aspas(txt: str) -> str:
    return txt.replace("'", "''")


for _, r in catalogo.iterrows():
    try:
        spark.sql(f"ALTER TABLE {DESTINO}.{r['tabela']} ALTER COLUMN {r['coluna']} COMMENT '{aspas(r['descricao'])}'")
    except Exception as e:  # o comentário no catálogo é um extra; o CSV abaixo é o entregável
        print("Sem comentário em", r["tabela"], r["coluna"], "->", str(e)[:80])
        break

os.makedirs(f"{BASE}/catalogo", exist_ok=True)
catalogo.to_csv(f"{BASE}/catalogo/catalogo_dados.csv", index=False, encoding="utf-8")
print("Catálogo salvo em", f"{BASE}/catalogo/catalogo_dados.csv")
display(spark.createDataFrame(catalogo)) if "display" in globals() else None

# COMMAND ----------

# MAGIC %md
# MAGIC ## 7. Validação depois da carga (evidência)

# COMMAND ----------

display(spark.sql(f"""
    SELECT 'fato_cve' AS tabela, COUNT(*) AS linhas FROM {DESTINO}.fato_cve UNION ALL
    SELECT 'dim_tempo', COUNT(*) FROM {DESTINO}.dim_tempo UNION ALL
    SELECT 'dim_severidade', COUNT(*) FROM {DESTINO}.dim_severidade UNION ALL
    SELECT 'dim_fornecedor', COUNT(*) FROM {DESTINO}.dim_fornecedor UNION ALL
    SELECT 'dim_cwe', COUNT(*) FROM {DESTINO}.dim_cwe UNION ALL
    SELECT 'ponte_cve_cwe', COUNT(*) FROM {DESTINO}.ponte_cve_cwe UNION ALL
    SELECT 'stg_nvd_cve', COUNT(*) FROM {DESTINO}.stg_nvd_cve UNION ALL
    SELECT 'stg_kev', COUNT(*) FROM {DESTINO}.stg_kev
"""))

# COMMAND ----------

# Integridade referencial: todas as contagens abaixo devem ser 0
display(spark.sql(f"""
    SELECT
      SUM(CASE WHEN s.sk_severidade IS NULL THEN 1 ELSE 0 END) AS sem_severidade,
      SUM(CASE WHEN p.sk_data IS NULL THEN 1 ELSE 0 END) AS sem_data_publicacao,
      SUM(CASE WHEN f.sk_data_kev IS NOT NULL AND k.sk_data IS NULL THEN 1 ELSE 0 END) AS sem_data_kev,
      SUM(CASE WHEN d.sk_fornecedor IS NULL THEN 1 ELSE 0 END) AS sem_fornecedor
    FROM {DESTINO}.fato_cve f
    LEFT JOIN {DESTINO}.dim_severidade s ON f.sk_severidade = s.sk_severidade
    LEFT JOIN {DESTINO}.dim_tempo p ON f.sk_data_publicacao = p.sk_data
    LEFT JOIN {DESTINO}.dim_tempo k ON f.sk_data_kev = k.sk_data
    LEFT JOIN {DESTINO}.dim_fornecedor d ON f.sk_fornecedor = d.sk_fornecedor
"""))

# COMMAND ----------

# Amostra do modelo funcionando: CVEs por faixa (v3.1) e quantas chegaram ao KEV
display(spark.sql(f"""
    SELECT s.faixa, COUNT(*) AS cves, SUM(CAST(f.esta_no_kev AS INT)) AS no_kev
    FROM {DESTINO}.fato_cve f JOIN {DESTINO}.dim_severidade s ON f.sk_severidade = s.sk_severidade
    WHERE s.versao_cvss = '3.1'
    GROUP BY s.faixa, s.ordem_faixa ORDER BY s.ordem_faixa
"""))
