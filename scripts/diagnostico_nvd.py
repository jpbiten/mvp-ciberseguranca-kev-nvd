# Diagnóstico exploratório dos arquivos brutos do NVD (rodado no Databricks antes da modelagem).
# Conta versões de CVSS, ausência de CWE, status e CVEs por ano; orientou as regras R1, R3 e R5 do notebook 02.
import collections
import gzip
import json
import os

BASE = "/Volumes/workspace/mvp_ciber/raw"
METRICAS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

arqs = sorted(f for f in os.listdir(f"{BASE}/nvd") if f.endswith(".json.gz"))
cont = collections.Counter()
anos = collections.Counter()

for nome in arqs:
    with gzip.open(f"{BASE}/nvd/{nome}", "rb") as f:
        pag = json.loads(f.read())
    for item in pag["vulnerabilities"]:
        c = item["cve"]
        m = c.get("metrics", {})
        cont["total"] += 1
        cont["status: " + c.get("vulnStatus", "?")] += 1
        for k in METRICAS:
            if k in m:
                cont[k] += 1
        if not any(k in m for k in METRICAS):
            cont["sem nenhuma metrica CVSS"] += 1
        if not c.get("weaknesses"):
            cont["sem weaknesses (CWE)"] += 1
        if "cisaExploitAdd" in c:
            cont["marcada como KEV no proprio NVD"] += 1
        anos[c["published"][:4]] += 1

print("Paginas lidas:", len(arqs))
for k, v in sorted(cont.items()):
    print(f"{k}: {v}")
print("\nCVEs por ano de publicacao:", dict(sorted(anos.items())))
