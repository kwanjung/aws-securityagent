#!/usr/bin/env python3
import json, subprocess, os, re
SPACE = "SPACE_ID"
JOB = "JOB_ID"

REGION = os.environ.get("AWS_REGION", "us-east-1")
def aws(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(r.stdout) if r.returncode == 0 else None
resp = aws(["aws", "securityagent", "list-findings",
            "--agent-space-id", SPACE, "--pentest-job-id", JOB, 
            "--region", REGION, "--output", "json"])
findings = resp.get("findingsSummaries", [])

print(f"\uCD1D {len(findings)}\uAC1C Finding\\n")
for f in findings:
    print(f"{f.get('riskType'):<30}|{f.get('riskLevel'):<12}|{f.get('name')}")
