# Databricks notebook source
# MAGIC %md
# MAGIC # 01 - Coleta de dados (KEV + NVD)
# MAGIC
# MAGIC **MVP - Segurança cibernética** | Universidade de Brasília - Engenharia de Produção
# MAGIC **Autor:** João Pedro Ferreira Bitencourt (matrícula 211068047)
# MAGIC
# MAGIC Este notebook coleta e persiste, na nuvem (Volume do Unity Catalog), os dois conjuntos de dados do projeto:
# MAGIC
# MAGIC | Fonte | O que é | Como é coletado |
# MAGIC |---|---|---|
# MAGIC | **CISA KEV** | Catálogo de vulnerabilidades comprovadamente exploradas | Download do arquivo JSON oficial |
# MAGIC | **NVD (NIST)** | Base nacional de vulnerabilidades dos EUA (CVEs, CVSS, CWE) | API REST 2.0, paginada |
# MAGIC
# MAGIC Os dados brutos são gravados **sem alteração** (camada raw). Nenhuma transformação acontece aqui.
# MAGIC
# MAGIC > This product uses the NVD API but is not endorsed or certified by the NVD.
# MAGIC
# MAGIC **Reprodutibilidade:** ao final, o notebook gera um manifesto com data, volume e formato dos arquivos.
# MAGIC **Retomada:** se a execução for interrompida, basta rodar de novo; páginas do NVD já baixadas são puladas.

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1. Configuração

# COMMAND ----------

import gzip
import hashlib
import json
import os
import time
from datetime import datetime, timezone

import requests

# --- Destino dos dados (Unity Catalog). Se der erro de catálogo, confira o nome em "Catalog". ---
CATALOG = "workspace"
SCHEMA = "mvp_ciber"
VOLUME = "raw"
BASE = f"/Volumes/{CATALOG}/{SCHEMA}/{VOLUME}"

# --- Fontes ---
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE = 2000  # máximo permitido pela API

# --- Chave opcional da API do NVD (gratuita). Sem chave a coleta funciona, só é mais lenta. ---
dbutils.widgets.text("nvd_api_key", "", "Chave da API do NVD (opcional)")
NVD_API_KEY = dbutils.widgets.get("nvd_api_key").strip()
PAUSA_ENTRE_PAGINAS = 0.8 if NVD_API_KEY else 6.5  # segundos; respeita o limite de requisições do NVD

spark.sql(f"CREATE SCHEMA IF NOT EXISTS {CATALOG}.{SCHEMA}")
spark.sql(f"CREATE VOLUME IF NOT EXISTS {CATALOG}.{SCHEMA}.{VOLUME}")
for pasta in ("kev", "nvd", "manifesto"):
    os.makedirs(f"{BASE}/{pasta}", exist_ok=True)

print("Destino:", BASE)
print("Usando chave do NVD:", "sim" if NVD_API_KEY else "não (pausa de 6,5 s entre páginas)")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. Coleta do catálogo CISA KEV

# COMMAND ----------

inicio_kev = datetime.now(timezone.utc)
resp = requests.get(KEV_URL, timeout=120)
resp.raise_for_status()
conteudo_kev = resp.content

kev_json = json.loads(conteudo_kev)
kev_path = f"{BASE}/kev/known_exploited_vulnerabilities_{inicio_kev:%Y%m%d}.json"
with open(kev_path, "wb") as f:
    f.write(conteudo_kev)

kev_info = {
    "fonte": "CISA Known Exploited Vulnerabilities (KEV)",
    "url": KEV_URL,
    "coletado_em_utc": inicio_kev.isoformat(timespec="seconds"),
    "formato_original": "JSON",
    "arquivo": kev_path,
    "bytes": len(conteudo_kev),
    "sha256": hashlib.sha256(conteudo_kev).hexdigest(),
    "registros": len(kev_json.get("vulnerabilities", [])),
    "versao_catalogo": kev_json.get("catalogVersion"),
    "data_lancamento_catalogo": kev_json.get("dateReleased"),
}
print(json.dumps(kev_info, indent=2, ensure_ascii=False))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. Coleta do NVD (API 2.0, paginada)
# MAGIC
# MAGIC Cada página (até 2.000 CVEs) é gravada compactada (`.json.gz`) no Volume, exatamente como veio da API.

# COMMAND ----------

headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}


def baixar_pagina_nvd(start_index: int) -> bytes:
    """Baixa uma página do NVD, com novas tentativas em caso de limite de requisições."""
    params = {"startIndex": start_index, "resultsPerPage": NVD_PAGE_SIZE}
    for tentativa in range(1, 7):
        r = requests.get(NVD_URL, params=params, headers=headers, timeout=180)
        if r.status_code == 200:
            return r.content
        if r.status_code in (403, 429, 503):
            espera = 30 * tentativa
            print(f"  HTTP {r.status_code} em startIndex={start_index}; aguardando {espera}s (tentativa {tentativa}/6)")
            time.sleep(espera)
            continue
        r.raise_for_status()
    raise RuntimeError(f"Falha ao baixar startIndex={start_index} após 6 tentativas")


def caminho_pagina(start_index: int) -> str:
    return f"{BASE}/nvd/cves_{start_index:07d}.json.gz"


def gravar_pagina(start_index: int, bruto: bytes) -> None:
    """Grava em arquivo temporário e renomeia, para que uma interrupção não deixe página corrompida."""
    destino = caminho_pagina(start_index)
    with open(destino + ".tmp", "wb") as f:
        f.write(gzip.compress(bruto))
    os.replace(destino + ".tmp", destino)


inicio_nvd = datetime.now(timezone.utc)

# Página 0: também informa o total de CVEs existentes no momento da coleta.
if os.path.exists(caminho_pagina(0)):
    with gzip.open(caminho_pagina(0), "rb") as f:
        primeira = json.loads(f.read())
    print("Página 0 já existe; reaproveitando.")
else:
    bruto = baixar_pagina_nvd(0)
    primeira = json.loads(bruto)
    gravar_pagina(0, bruto)

total_nvd = primeira["totalResults"]
timestamp_nvd = primeira.get("timestamp")
print(f"Total de CVEs no NVD: {total_nvd} | timestamp da base: {timestamp_nvd}")

for start in range(NVD_PAGE_SIZE, total_nvd, NVD_PAGE_SIZE):
    if os.path.exists(caminho_pagina(start)):
        continue  # já baixada em execução anterior
    time.sleep(PAUSA_ENTRE_PAGINAS)
    bruto = baixar_pagina_nvd(start)
    gravar_pagina(start, bruto)
    print(f"  startIndex={start} gravado ({len(bruto)/1e6:.1f} MB brutos)")

fim_nvd = datetime.now(timezone.utc)
print("Coleta do NVD concluída.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4. Manifesto da coleta
# MAGIC
# MAGIC Registra data, volume e formato original dos arquivos (exigência do enunciado do MVP).

# COMMAND ----------

arquivos_nvd = sorted(f for f in os.listdir(f"{BASE}/nvd") if f.endswith(".json.gz"))
bytes_nvd = sum(os.path.getsize(f"{BASE}/nvd/{f}") for f in arquivos_nvd)

nvd_info = {
    "fonte": "NVD - National Vulnerability Database (NIST), API REST 2.0",
    "url": NVD_URL,
    "coletado_em_utc": inicio_nvd.isoformat(timespec="seconds"),
    "concluido_em_utc": fim_nvd.isoformat(timespec="seconds"),
    "formato_original": "JSON (armazenado como .json.gz, uma página por arquivo)",
    "paginas_gravadas": len(arquivos_nvd),
    "paginas_esperadas": -(-total_nvd // NVD_PAGE_SIZE),
    "bytes_compactados": bytes_nvd,
    "total_cves_informado_pela_api": total_nvd,
    "timestamp_da_base": timestamp_nvd,
    "usou_chave_api": bool(NVD_API_KEY),
    "aviso_atribuicao": "This product uses the NVD API but is not endorsed or certified by the NVD.",
}

manifesto = {"kev": kev_info, "nvd": nvd_info}
manifesto_path = f"{BASE}/manifesto/coleta_manifesto.json"
with open(manifesto_path, "w", encoding="utf-8") as f:
    json.dump(manifesto, f, indent=2, ensure_ascii=False)

if nvd_info["paginas_gravadas"] != nvd_info["paginas_esperadas"]:
    print("ATENÇÃO: número de páginas gravadas difere do esperado. Rode a seção 3 novamente.")

print(json.dumps(manifesto, indent=2, ensure_ascii=False))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 5. Conferência final (evidência de persistência na nuvem)

# COMMAND ----------

display(dbutils.fs.ls(f"{BASE}/kev"))
display(dbutils.fs.ls(f"{BASE}/manifesto"))
print(f"{len(arquivos_nvd)} arquivos do NVD em {BASE}/nvd ({bytes_nvd/1e6:.0f} MB compactados)")
