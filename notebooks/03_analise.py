# Databricks notebook source
# MAGIC %md
# MAGIC # 03 - Análise: qualidade dos dados e respostas às perguntas
# MAGIC
# MAGIC **MVP - Segurança cibernética** | Universidade de Brasília - Engenharia de Produção
# MAGIC **Autor:** João Pedro Ferreira Bitencourt (matrícula 211068047)
# MAGIC
# MAGIC Este notebook lê o modelo dimensional gravado pelo notebook 02 e:
# MAGIC 1. avalia a **qualidade dos dados por atributo** (nulos, domínio, consistência);
# MAGIC 2. responde às três perguntas de negócio;
# MAGIC 3. salva tabelas (CSV) e gráficos (PNG) em `/Volumes/workspace/mvp_ciber/raw/resultados`.
# MAGIC
# MAGIC | # | Pergunta |
# MAGIC |---|---|
# MAGIC | P1 | Que proporção das CVEs chega ao KEV e como ela varia por faixa de severidade CVSS? |
# MAGIC | P2 | Quanto tempo, em mediana, passa entre a publicação de uma CVE e sua entrada no KEV, e esse prazo mudou ao longo dos anos? |
# MAGIC | P3 | As CVEs do KEV associadas a ransomware têm um perfil distinto das demais (severidade, tipo de falha, fornecedor)? |
# MAGIC
# MAGIC A discussão dos resultados está no README do repositório.
# MAGIC
# MAGIC > This product uses the NVD API but is not endorsed or certified by the NVD.

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1. Configuração e leitura do modelo

# COMMAND ----------

import json
import os

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

CATALOG = "workspace"
SCHEMA = "mvp_ciber"
DESTINO = f"{CATALOG}.{SCHEMA}"
SAIDA = f"/Volumes/{CATALOG}/{SCHEMA}/raw/resultados"
os.makedirs(SAIDA, exist_ok=True)

FAIXAS = ["Crítica", "Alta", "Média", "Baixa", "Nenhuma", "Sem CVSS"]
V3 = ["3.1", "3.0"]  # mesma escala de severidade; análise principal da P1 e da P3
ANO_ATUAL = pd.Timestamp.today().year
RESUMO = {}  # números-chave, impressos ao final


def mostrar(df: pd.DataFrame, nome: str = None):
    """Exibe a tabela e, se tiver nome, salva em CSV. Colunas de texto viram str para o display não falhar."""
    df = df.reset_index(drop=True).copy()
    for c in df.columns:
        if df[c].dtype == object:
            df[c] = df[c].astype(str)
    if nome:
        df.to_csv(f"{SAIDA}/{nome}.csv", index=False, encoding="utf-8")
    try:
        display(df)
    except NameError:
        print(df.to_string())


def salvar_figura(fig, nome: str):
    fig.savefig(f"{SAIDA}/{nome}.png", dpi=150, bbox_inches="tight")
    plt.show()


base = spark.sql(f"""
    SELECT f.cve_id, f.score_cvss, f.status_nvd, f.esta_no_kev, f.uso_ransomware,
           f.dias_ate_kev, f.lote_inicial_kev,
           s.versao_cvss, s.faixa, s.ordem_faixa,
           tp.ano AS ano_publicacao, tk.ano AS ano_kev,
           d.fornecedor, d.produto
    FROM {DESTINO}.fato_cve f
    JOIN {DESTINO}.dim_severidade s ON f.sk_severidade = s.sk_severidade
    JOIN {DESTINO}.dim_tempo tp ON f.sk_data_publicacao = tp.sk_data
    LEFT JOIN {DESTINO}.dim_tempo tk ON f.sk_data_kev = tk.sk_data
    JOIN {DESTINO}.dim_fornecedor d ON f.sk_fornecedor = d.sk_fornecedor
""").toPandas()

for c in ["esta_no_kev", "lote_inicial_kev"]:
    base[c] = base[c].fillna(False).astype(bool)
for c in ["dias_ate_kev", "ano_kev", "ano_publicacao", "ordem_faixa"]:
    base[c] = pd.to_numeric(base[c], errors="coerce").astype("Int64")
base["score_cvss"] = pd.to_numeric(base["score_cvss"], errors="coerce")

cwe_kev = spark.sql(f"""
    SELECT p.cve_id, p.cwe_id, c.tipo_cwe, p.fonte_cwe
    FROM {DESTINO}.ponte_cve_cwe p
    JOIN {DESTINO}.dim_cwe c ON p.cwe_id = c.cwe_id
    JOIN {DESTINO}.fato_cve f ON p.cve_id = f.cve_id
    WHERE f.esta_no_kev = true
""").toPandas()

stg_kev = spark.sql(f"SELECT * FROM {DESTINO}.stg_kev").toPandas()
for c in ["data_inclusao_kev", "prazo_correcao"]:
    stg_kev[c] = pd.to_datetime(stg_kev[c], errors="coerce")

kev = base[base["esta_no_kev"]].copy()
print(f"CVEs na fato: {len(base)} | no KEV: {len(kev)} | associações CVE x CWE no KEV: {len(cwe_kev)}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. Qualidade dos dados por atributo
# MAGIC
# MAGIC Para cada atributo: tipo, nulos, valores distintos, mínimo e máximo e quantidade de valores **fora do domínio** definido no catálogo de dados.

# COMMAND ----------


def perfil(df: pd.DataFrame, tabela: str, regras: dict) -> pd.DataFrame:
    linhas = []
    n = len(df)
    for col in df.columns:
        s = df[col]
        validos = s.dropna()
        mn = mx = ""
        if len(validos) and (pd.api.types.is_datetime64_any_dtype(s)
                             or (pd.api.types.is_numeric_dtype(s) and not pd.api.types.is_bool_dtype(s))):
            mn, mx = validos.min(), validos.max()
            if pd.api.types.is_datetime64_any_dtype(s):
                mn, mx = mn.date(), mx.date()
        fora = ""
        if col in regras:
            fora = str(int((~regras[col](validos).astype(bool)).sum()))
        linhas.append({
            "tabela": tabela, "atributo": col, "tipo": str(s.dtype),
            "nulos": int(s.isna().sum()), "pct_nulos": round(100 * s.isna().mean(), 2) if n else 0.0,
            "distintos": int(s.nunique()), "minimo": str(mn), "maximo": str(mx), "fora_do_dominio": fora,
        })
    return pd.DataFrame(linhas)


REGRAS_FATO = {
    "cve_id": lambda s: s.astype(str).str.match(r"^CVE-\d{4}-\d{4,}$"),
    "score_cvss": lambda s: s.between(0, 10),
    "status_nvd": lambda s: s.isin(["Analyzed", "Modified", "Deferred", "Awaiting Analysis",
                                    "Undergoing Analysis", "Received"]),
    "uso_ransomware": lambda s: s.isin(["Conhecido", "Desconhecido", "Fora do KEV"]),
    "versao_cvss": lambda s: s.isin(["3.1", "3.0", "4.0", "2.0", "N/A"]),
    "faixa": lambda s: s.isin(FAIXAS),
    "ano_publicacao": lambda s: s.between(1988, ANO_ATUAL),
    "ano_kev": lambda s: s.between(2021, ANO_ATUAL),
}
REGRAS_KEV = {
    "cve_id": lambda s: s.astype(str).str.match(r"^CVE-\d{4}-\d{4,}$"),
    "uso_ransomware": lambda s: s.isin(["Conhecido", "Desconhecido"]),
    "data_inclusao_kev": lambda s: s >= pd.Timestamp("2021-11-03"),
    "fornecedor": lambda s: s.astype(str).str.len() > 0,
    "produto": lambda s: s.astype(str).str.len() > 0,
}

qualidade = pd.concat([perfil(base, "fato_cve (+ dimensões)", REGRAS_FATO),
                       perfil(stg_kev, "stg_kev", REGRAS_KEV)], ignore_index=True)
mostrar(qualidade, "qualidade_por_atributo")

# COMMAND ----------

# Regras de consistência entre atributos (contagem de violações)
fora_kev = ~base["esta_no_kev"]
consistencia = pd.DataFrame([
    ("dias_ate_kev preenchido se e somente se a CVE está no KEV",
     int((base["dias_ate_kev"].notna() != base["esta_no_kev"]).sum())),
    ("uso_ransomware = 'Fora do KEV' se e somente se a CVE não está no KEV",
     int(((base["uso_ransomware"] == "Fora do KEV") != fora_kev).sum())),
    ("fornecedor = 'Não informado' se e somente se a CVE não está no KEV",
     int(((base["fornecedor"] == "Não informado") != fora_kev).sum())),
    ("score_cvss nulo se e somente se faixa = 'Sem CVSS'",
     int((base["score_cvss"].isna() != (base["faixa"] == "Sem CVSS")).sum())),
    ("CVEs do KEV com dias_ate_kev negativo (entraram no KEV antes da publicação no NVD)",
     int((kev["dias_ate_kev"] < 0).sum())),
    ("CVEs do KEV sem CVSS v3.x", int((~kev["versao_cvss"].isin(V3)).sum())),
    ("CVEs do KEV sem nenhum CWE específico (só genérico do NVD ou nenhum)",
     int(len(kev) - cwe_kev.loc[cwe_kev["tipo_cwe"] == "Específico", "cve_id"].nunique())),
], columns=["regra", "ocorrencias"])
mostrar(consistencia, "qualidade_consistencia")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. P1 - Proporção de CVEs que chega ao KEV, por faixa de severidade
# MAGIC
# MAGIC Base: CVEs com CVSS v3.x (v3.1 ou v3.0), que usam a mesma escala de faixas. As demais versões aparecem na tabela complementar.

# COMMAND ----------

total, total_kev = len(base), int(base["esta_no_kev"].sum())
RESUMO["P1_taxa_geral_pct"] = round(100 * total_kev / total, 3)
print(f"Taxa geral: {total_kev} de {total} CVEs no KEV = {RESUMO['P1_taxa_geral_pct']}%")

v3 = base[base["versao_cvss"].isin(V3)]
p1 = (v3.groupby("faixa").agg(cves=("cve_id", "size"), no_kev=("esta_no_kev", "sum"))
        .reindex(["Crítica", "Alta", "Média", "Baixa", "Nenhuma"]).dropna().reset_index())
p1[["cves", "no_kev"]] = p1[["cves", "no_kev"]].astype(int)
taxa_v3 = p1["no_kev"].sum() / p1["cves"].sum()
p1["taxa_kev_pct"] = (100 * p1["no_kev"] / p1["cves"]).round(3)
p1["participacao_no_kev_pct"] = (100 * p1["no_kev"] / p1["no_kev"].sum()).round(1)
p1["vezes_a_media"] = (p1["no_kev"] / p1["cves"] / taxa_v3).round(2)
mostrar(p1, "p1_taxa_por_faixa_v3")

# Cobertura x esforço: corrigir das faixas mais graves para as menos graves
linhas = []
for k in range(1, len(p1) + 1):
    sel = p1.iloc[:k]
    linhas.append({
        "estrategia": "Corrigir " + " + ".join(sel["faixa"]),
        "cves_a_corrigir": int(sel["cves"].sum()),
        "pct_do_esforco": round(100 * sel["cves"].sum() / p1["cves"].sum(), 1),
        "kev_cobertas": int(sel["no_kev"].sum()),
        "pct_do_kev_coberto": round(100 * sel["no_kev"].sum() / p1["no_kev"].sum(), 1),
    })
p1_cobertura = pd.DataFrame(linhas)
mostrar(p1_cobertura, "p1_cobertura_esforco")
RESUMO["P1_so_criticas_pct_kev"] = float(p1_cobertura.loc[0, "pct_do_kev_coberto"])
RESUMO["P1_criticas_altas_pct_kev"] = float(p1_cobertura.loc[1, "pct_do_kev_coberto"])
RESUMO["P1_criticas_altas_pct_esforco"] = float(p1_cobertura.loc[1, "pct_do_esforco"])

# COMMAND ----------

# Complementar: todas as versões do CVSS
p1_versoes = (base.groupby(["versao_cvss", "faixa", "ordem_faixa"])
                  .agg(cves=("cve_id", "size"), no_kev=("esta_no_kev", "sum")).reset_index()
                  .sort_values(["versao_cvss", "ordem_faixa"], ascending=[True, False]))
p1_versoes["no_kev"] = p1_versoes["no_kev"].astype(int)
p1_versoes["taxa_kev_pct"] = (100 * p1_versoes["no_kev"] / p1_versoes["cves"]).round(3)
mostrar(p1_versoes.drop(columns="ordem_faixa"), "p1_todas_versoes")

# COMMAND ----------

fig, (a1, a2) = plt.subplots(1, 2, figsize=(13, 4.5))
a1.bar(p1["faixa"], p1["taxa_kev_pct"], color="#4C72B0")
for i, v in enumerate(p1["taxa_kev_pct"]):
    a1.text(i, v, f"{v:.2f}%", ha="center", va="bottom", fontsize=9)
a1.set_title("P1 - % das CVEs que chegam ao KEV (CVSS v3.x)")
a1.set_ylabel("% no KEV")
a1.spines[["top", "right"]].set_visible(False)

a2.plot(p1_cobertura["pct_do_esforco"], p1_cobertura["pct_do_kev_coberto"], marker="o", color="#C44E52")
rotulos = ["Só Crítica", "+ Alta", "+ Média"]  # Baixa e Nenhuma ficam sobrepostas perto de 100%
deslocamentos = [(6, -14), (6, -14), (-8, 8)]
for rot, desl, (_, r) in zip(rotulos, deslocamentos, p1_cobertura.head(3).iterrows()):
    a2.annotate(f"{rot}: {r['pct_do_kev_coberto']:.1f}% do KEV", (r["pct_do_esforco"], r["pct_do_kev_coberto"]),
                textcoords="offset points", xytext=desl, fontsize=8, ha="left" if desl[0] > 0 else "right")
a2.plot([0, 100], [0, 100], ls="--", color="grey", lw=0.8)
a2.set_xlim(0, 105)
a2.set_ylim(0, 105)
a2.set_title("P1 - Cobertura do KEV x esforço de correção")
a2.set_xlabel("% das CVEs corrigidas")
a2.set_ylabel("% das CVEs do KEV cobertas")
a2.spines[["top", "right"]].set_visible(False)
salvar_figura(fig, "p1_severidade_kev")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4. P2 - Tempo entre a publicação e a entrada no KEV
# MAGIC
# MAGIC - O **lote inicial** (CVEs incluídas no dia de criação do catálogo, 03/11/2021) mede estoque acumulado, e não tempo de reação. Por isso é analisado separadamente.
# MAGIC - Valores negativos (CVE incluída no KEV antes da publicação no NVD) são mantidos.
# MAGIC - **Viés de censura:** CVEs recentes ainda podem entrar no KEV no futuro, o que tende a reduzir as medianas dos anos mais recentes quando a análise é feita por ano de publicação.

# COMMAND ----------


def resumo_dias(g: pd.DataFrame) -> dict:
    d = g["dias_ate_kev"].astype(float)
    return {
        "cves": int(len(d)),
        "mediana_dias": float(d.median()),
        "p25_dias": float(d.quantile(0.25)),
        "p75_dias": float(d.quantile(0.75)),
        "pct_ate_7_dias": round(100 * float((d <= 7).mean()), 1),
        "pct_ate_30_dias": round(100 * float((d <= 30).mean()), 1),
        "pct_negativos": round(100 * float((d < 0).mean()), 1),
    }


def por_grupo(df: pd.DataFrame, col: str) -> pd.DataFrame:
    return pd.DataFrame([{col: int(k), **resumo_dias(g)} for k, g in df.groupby(col)])


k2 = kev.dropna(subset=["dias_ate_kev"])
lote = k2["lote_inicial_kev"]
p2_geral = pd.DataFrame([
    {"grupo": "Todo o KEV", **resumo_dias(k2)},
    {"grupo": "Sem o lote inicial", **resumo_dias(k2[~lote])},
    {"grupo": "Só o lote inicial (03/11/2021)", **resumo_dias(k2[lote])},
])
mostrar(p2_geral, "p2_geral")
RESUMO["P2_mediana_dias_sem_lote"] = float(p2_geral.loc[1, "mediana_dias"])
RESUMO["P2_pct_ate_30_dias_sem_lote"] = float(p2_geral.loc[1, "pct_ate_30_dias"])

p2_ano_kev = por_grupo(k2[~lote], "ano_kev")
mostrar(p2_ano_kev, "p2_por_ano_inclusao")

# CVEs publicadas depois da criação do KEV: tempo de reação a vulnerabilidades novas
p2_ano_pub = por_grupo(k2[k2["ano_publicacao"] >= 2022], "ano_publicacao")
mostrar(p2_ano_pub, "p2_por_ano_publicacao_desde_2022")

# COMMAND ----------

fig, (a1, a2) = plt.subplots(1, 2, figsize=(13, 4.5))
x = p2_ano_kev["ano_kev"].astype(str)
a1.plot(x, p2_ano_kev["mediana_dias"], marker="o", color="#4C72B0", label="Mediana")
a1.fill_between(x, p2_ano_kev["p25_dias"], p2_ano_kev["p75_dias"], color="#4C72B0", alpha=0.15,
                label="Entre p25 e p75")
a1.set_title("P2 - Dias até o KEV, por ano de inclusão (sem lote inicial)")
a1.set_ylabel("dias")
a1.legend(frameon=False)
a1.spines[["top", "right"]].set_visible(False)

x2 = p2_ano_pub["ano_publicacao"].astype(str)
a2.bar(x2, p2_ano_pub["pct_ate_30_dias"], color="#55A868")
for i, v in enumerate(p2_ano_pub["pct_ate_30_dias"]):
    a2.text(i, v, f"{v:.0f}%", ha="center", va="bottom", fontsize=9)
a2.set_title("P2 - % incluídas em até 30 dias, por ano de publicação")
a2.set_ylabel("% das CVEs do KEV")
a2.set_ylim(0, 105)
a2.spines[["top", "right"]].set_visible(False)
salvar_figura(fig, "p2_tempo_ate_kev")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 5. P3 - Perfil das CVEs ligadas a ransomware
# MAGIC
# MAGIC Compara, dentro do KEV, as CVEs com uso **Conhecido** em ransomware e as com uso **Desconhecido**. Desconhecido significa "sem evidência pública", e não "nunca usado".

# COMMAND ----------

GRUPOS = ["Conhecido", "Desconhecido"]
linhas = []
for g in GRUPOS:
    d = kev[kev["uso_ransomware"] == g]
    d3 = d[d["versao_cvss"].isin(V3)]
    forn = d["fornecedor"].value_counts()
    linhas.append({
        "uso_ransomware": g,
        "cves": int(len(d)),
        "pct_do_kev": round(100 * len(d) / len(kev), 1),
        "score_medio_v3": round(float(d3["score_cvss"].mean()), 2),
        "score_mediano_v3": float(d3["score_cvss"].median()),
        "pct_criticas_v3": round(100 * float((d3["faixa"] == "Crítica").mean()), 1),
        "pct_altas_ou_criticas_v3": round(100 * float(d3["faixa"].isin(["Crítica", "Alta"]).mean()), 1),
        "mediana_dias_ate_kev_sem_lote": float(d.loc[~d["lote_inicial_kev"], "dias_ate_kev"].astype(float).median()),
        "fornecedores_distintos": int(forn.size),
        "pct_top5_fornecedores": round(100 * float(forn.head(5).sum() / forn.sum()), 1),
    })
p3_perfil = pd.DataFrame(linhas)
mostrar(p3_perfil, "p3_perfil")

# Distribuição das faixas (v3.x) em cada grupo, em %
k3 = kev[kev["versao_cvss"].isin(V3)]
tab_faixas = pd.crosstab(k3["uso_ransomware"], k3["faixa"]).reindex(columns=[f for f in FAIXAS if f in set(k3["faixa"])])
p3_faixas = (100 * tab_faixas.div(tab_faixas.sum(axis=1), axis=0)).round(1).reset_index()
mostrar(p3_faixas, "p3_faixas")

# Testes estatísticos (diferença entre os grupos)
try:
    from scipy.stats import chi2_contingency, mannwhitneyu
    _, p_faixas, _, _ = chi2_contingency(tab_faixas.values)
    _, p_score = mannwhitneyu(k3.loc[k3["uso_ransomware"] == "Conhecido", "score_cvss"].dropna(),
                              k3.loc[k3["uso_ransomware"] == "Desconhecido", "score_cvss"].dropna())
    RESUMO["P3_p_valor_faixas_qui_quadrado"] = float(p_faixas)
    RESUMO["P3_p_valor_score_mann_whitney"] = float(p_score)
    print(f"Qui-quadrado (faixas x grupo): p = {p_faixas:.4g} | Mann-Whitney (score): p = {p_score:.4g}")
except ImportError:
    print("scipy indisponível: testes estatísticos não calculados.")

# COMMAND ----------


def participacao(itens: pd.DataFrame, col: str, top: int = 10) -> pd.DataFrame:
    """% das CVEs de cada grupo associadas a cada item (CWE ou fornecedor); mostra a união dos top de cada grupo."""
    n = kev.groupby("uso_ransomware")["cve_id"].nunique()
    cont = itens.groupby(["uso_ransomware", col])["cve_id"].nunique().unstack(0).fillna(0)
    pct = (100 * cont / n[cont.columns]).round(1)
    topo = set()
    for g in GRUPOS:
        if g in pct.columns:
            topo |= set(pct[g].nlargest(top).index)
    saida = pct.loc[sorted(topo)].reindex(columns=GRUPOS).fillna(0.0)
    saida.columns = [f"pct_{g.lower()}" for g in GRUPOS]
    saida["diferenca_pp"] = (saida["pct_conhecido"] - saida["pct_desconhecido"]).round(1)
    return saida.sort_values("pct_conhecido", ascending=False).reset_index()


cwe_grupo = cwe_kev[cwe_kev["tipo_cwe"] == "Específico"].merge(kev[["cve_id", "uso_ransomware"]], on="cve_id")
p3_cwe = participacao(cwe_grupo, "cwe_id")
mostrar(p3_cwe, "p3_cwe")

p3_forn = participacao(kev[["cve_id", "uso_ransomware", "fornecedor"]], "fornecedor")
mostrar(p3_forn, "p3_fornecedores")

# COMMAND ----------

fig, (a1, a2) = plt.subplots(1, 2, figsize=(14, 5))
cores = {"Crítica": "#8C1C13", "Alta": "#C44E52", "Média": "#DD8452", "Baixa": "#CCB974", "Nenhuma": "#BBBBBB"}
esq = np.zeros(len(p3_faixas))
for faixa in [c for c in p3_faixas.columns if c != "uso_ransomware"]:
    a1.barh(p3_faixas["uso_ransomware"], p3_faixas[faixa], left=esq, color=cores.get(faixa, "#999999"), label=faixa)
    esq += p3_faixas[faixa].values
a1.set_title("P3 - Faixas de severidade (v3.x) dentro do KEV")
a1.set_xlabel("% das CVEs do grupo")
a1.legend(frameon=False, ncol=3, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.15))
a1.spines[["top", "right"]].set_visible(False)

top = p3_cwe.head(10).iloc[::-1]
y = np.arange(len(top))
a2.barh(y + 0.2, top["pct_conhecido"], height=0.4, color="#C44E52", label="Ransomware: Conhecido")
a2.barh(y - 0.2, top["pct_desconhecido"], height=0.4, color="#8172B3", label="Ransomware: Desconhecido")
a2.set_yticks(y, top["cwe_id"])
a2.set_title("P3 - CWEs mais frequentes (% das CVEs do grupo)")
a2.set_xlabel("% das CVEs do grupo")
a2.legend(frameon=False, fontsize=8)
a2.spines[["top", "right"]].set_visible(False)
salvar_figura(fig, "p3_ransomware")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 6. Resumo dos resultados (texto para copiar)
# MAGIC
# MAGIC Esta célula imprime os números-chave e todas as tabelas em texto, para conferência e para a redação do README.

# COMMAND ----------

with open(f"{SAIDA}/resumo.json", "w", encoding="utf-8") as f:
    json.dump(RESUMO, f, indent=2, ensure_ascii=False)

pd.set_option("display.width", 250)
pd.set_option("display.max_columns", 20)
print("RESUMO:", json.dumps(RESUMO, ensure_ascii=False))
for nome, t in [("CONSISTENCIA", consistencia), ("P1 FAIXAS", p1), ("P1 COBERTURA", p1_cobertura),
                ("P2 GERAL", p2_geral), ("P2 POR ANO DE INCLUSAO", p2_ano_kev),
                ("P2 POR ANO DE PUBLICACAO (desde 2022)", p2_ano_pub),
                ("P3 PERFIL", p3_perfil), ("P3 FAIXAS", p3_faixas), ("P3 CWE", p3_cwe), ("P3 FORNECEDORES", p3_forn)]:
    print(f"\n=== {nome} ===")
    print(t.to_string(index=False))
print("\nArquivos gerados em", SAIDA, ":", sorted(os.listdir(SAIDA)))
