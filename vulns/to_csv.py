import csv
import glob
import json

found = [f for f in glob.glob("./*.json")]
results = []

for pkg in found:
    with open(pkg) as f:
        p = json.loads(f.read())
        results.append({
            "name": p.get("name"),
            "cve_id": p.get("cve_id"),
            "cwe_id": p.get("cwe_id"),
            "publish_date": p.get("publish_date"),
            "license": p.get("license"),
            "csvv3": p.get("impact").get("cvss3_score"),
            "vector": p.get("impact").get("vector_string")
        })

with open("ochrona_vuln_summary_04262021.csv", "w") as f:
    writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
    writer.writeheader()
    for row in results:
        writer.writerow(row)
