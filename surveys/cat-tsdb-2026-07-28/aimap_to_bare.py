import json, sys

report = json.load(open(sys.argv[1]))
findings = []
for e in report.get("enum_results", []):
    for f in (e.get("findings") or []):
        findings.append({
            "id": f"{e['host']}:{e['port']}:{f['category']}:{f['title'][:40]}",
            "title": f["title"],
            "description": f"{f['title']}. {f.get('detail','')} Service: {e['service']} at {e['host']}:{e['port']}.".strip(),
            "target": f"{e['host']}:{e['port']}",
            "severity": f["severity"],
            "metadata": {"service": e["service"], "host": e["host"], "port": e["port"], "category": f["category"]},
        })

out = {"version": 1, "source": "aimap", "findings": findings}
json.dump(out, open(sys.argv[2], "w"), indent=2)
print(f"wrote {len(findings)} findings")
