"""
export_report_data.py -- saves Haltline's live data for the college report / presentation into
report_data/<date>/ (git-ignored: it holds IP addresses and device IDs).

    AWS_PROFILE=haltline python tools/export_report_data.py [--days 7]

Writes:
  request_log.csv       every Tier-2 request (time, device, IP, country, route, verdict, HTTP, ms, path taken)
  reports.csv           reports users chose to send (incl. "Report a problem")
  daily_summary.csv     per day: requests, by verdict, by source, distinct IPs, median/p95 ms
  lambda_metrics.json   CloudWatch: Lambda invocations / errors / duration per hour, last 24 h
  worker_metrics.json   Cloudflare: Worker requests / errors / CPU, last 24 h
  summary.md            the headline numbers, ready to paste into a report
Copies in the latest agent test, live attack test and resource-measurement outputs when present.
"""
import argparse
import csv
import datetime as dt
import json
import os
import re
import shutil
import statistics
import subprocess
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGION = "ap-south-1"


def aws(*args):
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    out = subprocess.run(["aws", *args, "--region", REGION, "--output", "json"], capture_output=True, text=True, env=env)
    if out.returncode:
        raise RuntimeError(out.stderr.strip()[:300])
    return json.loads(out.stdout or "{}")


def val(item, k):
    v = item.get(k) or {}
    return v.get("S") if "S" in v else v.get("N", "")


def query_day(prefix, day):
    items, start = [], None
    while True:
        args = ["dynamodb", "query", "--table-name", "haltline_events", "--key-condition-expression", "pk = :p",
                "--expression-attribute-values", json.dumps({":p": {"S": f"{prefix}#{day}"}})]
        if start:
            args += ["--exclusive-start-key", json.dumps(start)]
        page = aws(*args)
        items += page.get("Items", [])
        start = page.get("LastEvaluatedKey")
        if not start:
            return items


def tfvar(name):
    try:
        with open(os.path.join(ROOT, "infra", "aws", "secrets.tfvars"), encoding="utf-8") as f:
            m = re.search(rf'^\s*{name}\s*=\s*"([^"]*)"', f.read(), re.M)
        return m.group(1) if m else ""
    except OSError:
        return ""


def iso(ts):
    return dt.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S") if ts else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=7)
    a = ap.parse_args()
    today = dt.datetime.utcnow().date()
    out = os.path.join(ROOT, "report_data", today.isoformat())
    os.makedirs(out, exist_ok=True)

    # request log + reports
    req_cols = ["time", "device", "ip", "country", "asn", "route", "verdict", "http", "ms", "came_via", "trust", "reason"]
    rows, reports, daily = [], [], []
    for d in range(a.days - 1, -1, -1):
        day = (today - dt.timedelta(days=d)).isoformat()
        items = query_day("e", day)
        day_rows = [{"time": iso(val(i, "ts")), "device": val(i, "device"), "ip": val(i, "ip"), "country": val(i, "country"),
                     "asn": val(i, "asn"), "route": val(i, "path"), "verdict": val(i, "verdict"), "http": val(i, "status"),
                     "ms": val(i, "ms"), "came_via": {"cf": "Cloudflare Worker", "aws": "AWS Lambda (fallback)"}.get(val(i, "source"), val(i, "source")),
                     "trust": val(i, "verified"), "reason": val(i, "reason")} for i in items]
        rows += day_rows
        for i in query_day("r", day):
            reports.append({"time": iso(val(i, "ts")), "device": val(i, "device"), "name": val(i, "name"), "path": val(i, "path"),
                            "reason": val(i, "reason"), "ip": val(i, "ip")})
        if day_rows:
            ms = sorted(float(r["ms"]) for r in day_rows if r["ms"])
            daily.append({"day": day, "requests": len(day_rows),
                          "benign": sum(r["verdict"] == "BENIGN" for r in day_rows),
                          "kill": sum(r["verdict"] == "KILL" for r in day_rows),
                          "refused": sum(r["http"] not in ("200", "") for r in day_rows),
                          "via_cloudflare": sum(r["came_via"].startswith("Cloudflare") for r in day_rows),
                          "via_aws_fallback": sum(r["came_via"].startswith("AWS") for r in day_rows),
                          "devices": len({r["device"] for r in day_rows}), "distinct_ips": len({r["ip"] for r in day_rows if r["ip"]}),
                          "median_ms": round(statistics.median(ms), 2) if ms else "",
                          "p95_ms": round(ms[max(0, int(len(ms) * 0.95) - 1)], 2) if ms else ""})
    rows.sort(key=lambda r: r["time"])
    for name, data, cols in (("request_log.csv", rows, req_cols), ("reports.csv", reports, ["time", "device", "name", "path", "reason", "ip"]),
                             ("daily_summary.csv", daily, list(daily[0].keys()) if daily else ["day"])):
        with open(os.path.join(out, name), "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(data)

    # Lambda metrics, last 24 h, hourly
    end = dt.datetime.utcnow().replace(microsecond=0)
    lam = {}
    for metric, stats in (("Invocations", ["Sum"]), ("Errors", ["Sum"]), ("Throttles", ["Sum"]), ("Duration", ["Average", "Maximum"])):
        r = aws("cloudwatch", "get-metric-statistics", "--namespace", "AWS/Lambda", "--metric-name", metric,
                "--dimensions", "Name=FunctionName,Value=haltline-api", "--start-time", (end - dt.timedelta(hours=24)).isoformat() + "Z",
                "--end-time", end.isoformat() + "Z", "--period", "3600", "--statistics", *stats)
        lam[metric] = sorted(({"hour": p["Timestamp"], **{s: p[s] for s in stats}} for p in r.get("Datapoints", [])), key=lambda p: p["hour"])
    with open(os.path.join(out, "lambda_metrics.json"), "w", encoding="utf-8") as f:
        json.dump(lam, f, indent=2)

    # Cloudflare Worker metrics, last 24 h
    token = tfvar("cf_analytics_token") or tfvar("cf_api_token")
    q = {"query": "query($a:String!,$s:String!,$st:Time!,$en:Time!){viewer{accounts(filter:{accountTag:$a}){"
                  "workersInvocationsAdaptive(limit:10,filter:{datetime_geq:$st,datetime_lt:$en,scriptName:$s})"
                  "{sum{requests errors subrequests} quantiles{cpuTimeP50 cpuTimeP99}}}}}",
         "variables": {"a": tfvar("cf_account_id"), "s": tfvar("cf_worker_script"),
                       "st": (end - dt.timedelta(hours=24)).isoformat() + "Z", "en": end.isoformat() + "Z"}}
    try:
        req = urllib.request.Request("https://api.cloudflare.com/client/v4/graphql", data=json.dumps(q).encode(),
                                     headers={"Authorization": f"Bearer {token}", "content-type": "application/json"})
        worker = json.load(urllib.request.urlopen(req, timeout=20))
    except Exception as e:
        worker = {"error": str(e)}
    with open(os.path.join(out, "worker_metrics.json"), "w", encoding="utf-8") as f:
        json.dump(worker, f, indent=2)

    # test / measurement outputs already on disk
    for src, dst in ((os.path.join(ROOT, "build", "test_run.log"), "agent_tests.log"),
                     (os.path.join(ROOT, "build", "attack_run.log"), "live_attack_test.log"),
                     (os.path.join(ROOT, "build", "resource_samples.csv"), "resource_samples.csv")):
        if os.path.exists(src):
            shutil.copy(src, os.path.join(out, dst))

    # headline numbers
    w = (((worker.get("data") or {}).get("viewer") or {}).get("accounts") or [{}])[0].get("workersInvocationsAdaptive") or []
    inv = sum(p["Sum"] for p in lam["Invocations"])
    lines = [f"# Haltline live data, exported {dt.datetime.now():%Y-%m-%d %H:%M}", "",
             f"- Tier-2 requests logged (last {a.days} days): **{len(rows)}** from **{len({r['device'] for r in rows})}** device(s)"
             f" and **{len({r['ip'] for r in rows if r['ip']})}** distinct IPs",
             f"- Verdicts: {sum(r['verdict'] == 'BENIGN' for r in rows)} BENIGN, {sum(r['verdict'] == 'KILL' for r in rows)} KILL,"
             f" {sum(r['http'] not in ('200', '') for r in rows)} refused (signature / rate limit / revoked)",
             f"- Path taken: {sum(r['came_via'].startswith('Cloudflare') for r in rows)} via Cloudflare Worker,"
             f" {sum(r['came_via'].startswith('AWS') for r in rows)} via AWS Lambda fallback",
             f"- Lambda, last 24 h: {inv:.0f} invocations, {sum(p['Sum'] for p in lam['Errors']):.0f} errors,"
             f" {sum(p['Sum'] for p in lam['Throttles']):.0f} throttles",
             f"- Worker, last 24 h: {sum(x['sum']['requests'] for x in w)} requests, {sum(x['sum']['errors'] for x in w)} errors"
             if w else "- Worker metrics: not available", "", "Files: see the header of tools/export_report_data.py."]
    with open(os.path.join(out, "summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\nsaved to {out}")


if __name__ == "__main__":
    main()
