#!/usr/bin/env python3
"""
Stage 3v verification prober — Cat-Document-Loaders.

Load-bearing stage. A scan produces candidates; this produces findings.
For each candidate it:
  1. Re-probes the vendor-unique marker path (conjunctive: status + marker).
  2. CATCH-ALL NEGATIVE GUARD (LBot lesson, Insight #107/#108): probes a nonsense
     path; if it returns 200 with a body resembling the marker response, the host
     is a deception-fleet catch-all, REFUTED, not the platform.
  3. Confirms 200-with-data (the marker endpoint actually serves platform data).
  4. Extracts version for CVE scoping — READ ONLY. No XXE / SSRF / file-write
     payloads are fired at live third-party hosts (restraint ethic; Insight #68
     high-depth/low-breadth by choice). Version-in-CVE-range => "exploitable IF",
     recorded surface-open, access-not-exercised.

Run on Mullvad (observer-position gate / Insight #96): control hosts must return
their real content through the same exit, else L7 rewriting is suspected.
"""
import json, sys, socket, ssl, urllib.request, urllib.error, random, string, re
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 8
UA = "/doc-loaders (authorized assessment)"

# marker path, marker substrings (ALL must appear), version path, version regex
PLATFORMS = {
    "gotenberg": {
        "ports": [3000],
        "marker_path": "/health",
        "marker_all": [],                       # header-based; checked separately
        "marker_header": "Gotenberg-Trace",
        "version_path": "/version",
        "version_re": r"([0-9]+\.[0-9]+\.[0-9]+)",
        "cve_fixed": "8.32.0",                   # clears the SSRF+ExifTool cluster
        "cve": "CVE-2026-40281(10.0 RCE)/42595/42596(SSRF->IMDS)",
    },
    "grobid": {
        "ports": [8070],
        "marker_path": "/api/isalive",
        "marker_all": ["true"],
        "marker_not": ["<html"],
        "version_path": "/api/version",
        "version_re": r"([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9]+-g[0-9a-f]+)?)",
        "cve_fixed": None,
        "cve": "none cataloged; unauth /api/modelTraining = DoS surface",
    },
    "docling-serve": {
        "ports": [5001],
        "marker_path": "/openapi.json",
        "marker_all": ["/v1/convert/source"],
        "version_path": "/openapi.json",
        "version_re": r'"version"\s*:\s*"([0-9][^"]+)"',
        "cve_fixed": "docling-core>=2.48.4",
        "cve": "CVE-2026-24009(8.1 PyYAML RCE via core)",
    },
    "apache-tika": {
        "ports": [9998],
        "marker_path": "/tika",
        "marker_all": ["This is Tika Server", "Please PUT"],
        "version_path": "/version",
        "version_re": r"Apache Tika ([0-9][0-9.a-z-]+)",
        "cve_fixed": "3.2.2",
        "cve": "CVE-2025-66516(10.0 XXE->file-read/SSRF/IMDS)",
    },
    "unstructured-api": {
        "ports": [8000],
        "marker_path": "/general/openapi.json",
        "marker_all": ["Unstructured Pipeline API"],
        "version_path": "/general/openapi.json",
        "version_re": r'"version"\s*:\s*"([0-9][^"]+)"',
        "cve_fixed": "unstructured>=0.18.18",
        "cve": "CVE-2025-64712(9.8 path-trav->RCE in lib)",
    },
}


def fetch(ip, port, path, scheme="http"):
    url = f"{scheme}://{ip}:{port}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            body = r.read(65536).decode("utf-8", "replace")
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(65536).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, dict(e.headers or {}), body
    except Exception as e:
        return None, {"_err": str(e)}, ""


def verify(ip, port, plat):
    spec = PLATFORMS[plat]
    res = {"ip": ip, "port": port, "platform": plat, "verdict": "REFUTED",
           "reasons": [], "version": None, "cve": spec["cve"]}

    # try http then https
    for scheme in ("http", "https"):
        st, hdr, body = fetch(ip, port, spec["marker_path"], scheme)
        if st is None:
            continue
        res["scheme"] = scheme
        res["marker_status"] = st

        # header-marker platforms (gotenberg)
        if spec.get("marker_header"):
            hv = " ".join(f"{k}:{v}" for k, v in hdr.items())
            if spec["marker_header"].lower() in hv.lower():
                res["reasons"].append(f"header {spec['marker_header']} present")
            else:
                res["reasons"].append(f"header {spec['marker_header']} ABSENT")
                continue
        else:
            # body-marker conjunctive
            if st != 200:
                res["reasons"].append(f"marker path status {st} != 200")
                continue
            if not all(m in body for m in spec["marker_all"]):
                res["reasons"].append("marker substrings missing")
                continue
            if any(m in body for m in spec.get("marker_not", [])):
                res["reasons"].append("anti-marker present (FP shape)")
                continue
            res["reasons"].append("marker substrings present + 200")

        # CATCH-ALL NEGATIVE GUARD
        nonce = "/" + "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
        nst, nhdr, nbody = fetch(ip, port, nonce, scheme)
        if spec.get("marker_header"):
            nhv = " ".join(f"{k}:{v}" for k, v in nhdr.items())
            catchall = spec["marker_header"].lower() in nhv.lower() and nst == 200 and nbody == body
        else:
            catchall = nst == 200 and all(m in nbody for m in spec["marker_all"])
        if catchall:
            res["verdict"] = "REFUTED-CATCHALL"
            res["reasons"].append(f"nonsense path {nonce} also matched -> deception catch-all")
            return res
        res["reasons"].append(f"catch-all guard PASSED (nonce {nst})")

        # version scoping — READ ONLY
        vst, vhdr, vbody = fetch(ip, port, spec["version_path"], scheme)
        srv = vhdr.get("Server", "") + " " + hdr.get("Server", "")
        m = re.search(spec["version_re"], (vbody or "") + " " + srv)
        if m:
            res["version"] = m.group(1)

        res["verdict"] = "CONFIRMED-OPEN"
        return res

    res["reasons"].append("no scheme responded")
    return res


def main():
    targets = []  # (ip, port, platform)
    src = sys.argv[1] if len(sys.argv) > 1 else "-"
    fh = sys.stdin if src == "-" else open(src)
    for line in fh:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 3:
            ip, port, plat = parts[0], int(parts[1]), parts[2]
            if plat in PLATFORMS:
                targets.append((ip, port, plat))

    results = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = [ex.submit(verify, ip, port, plat) for ip, port, plat in targets]
        for f in futs:
            results.append(f.result())

    confirmed = [r for r in results if r["verdict"] == "CONFIRMED-OPEN"]
    catchall = [r for r in results if r["verdict"] == "REFUTED-CATCHALL"]
    print(json.dumps(results, indent=2))
    print(f"\n# {len(confirmed)} CONFIRMED-OPEN / {len(catchall)} catch-all / "
          f"{len(results)} probed", file=sys.stderr)
    for r in confirmed:
        vr = f"v{r['version']}" if r["version"] else "version-unknown"
        print(f"#   OPEN {r['platform']:16} {r['ip']}:{r['port']} {vr}  [{r['cve']}]",
              file=sys.stderr)


if __name__ == "__main__":
    main()
