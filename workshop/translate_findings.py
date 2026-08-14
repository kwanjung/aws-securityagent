#!/usr/bin/env python3
import json, subprocess, os
import boto3
SPACE = "SPACE_ID" # 워크샵 SpaceID 값 입력
JOB = "JOB_ID" # 워크샵 Pentest Job ID 값 입력
REGION = os.environ.get("AWS_REGION", "us-east-1")
MODEL_ID = "arn:aws:bedrock:us-east-1:[워크샵 Account ID로 변경]:inference-profile/us.anthropic.claude-opus-4-6-v1"  

bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")

def aws(cmd):
	r = subprocess.run(cmd, capture_output=True, text=True)
	return json.loads(r.stdout) if r.returncode == 0 else None

def translate_name(name):
	body = json.dumps({
		"anthropic_version": "bedrock-2023-05-31",
		"max_tokens": 200,
		"messages": [{"role": "user", "content": f"다음 보안 취약점 이름을 한국어로 간결하게 번역해 주세요. (번역 결과만 출력):\n{name}"}]
	})
	try:
		resp = bedrock.invoke_model(modelId=MODEL_ID, contentType="application/json", body=body)
		result = json.loads(resp["body"].read())
		return result.get("content", [{}])[0].get("text", name).strip()
	except Exception as e:
		return name

resp = aws(["aws", "securityagent", "list-findings",
"--agent-space-id", SPACE, "--pentest-job-id", JOB,
"--region", REGION, "--output", "json"])

findings = resp.get("findingsSummaries", [])

print(f"총 {len(findings)}개 Finding\n")
print(f"{'RiskType':<30}|{'RiskLevel':<12}|{'Confidence':<14}|{'Name (한국어)'}")
print("-" * 110)

for f in findings:
	name_kr = translate_name(f.get("name", "N/A"))
	print(f"{f.get('riskType','N/A'):<30}|{f.get('riskLevel','N/A'):<12}|{f.get('confidence','N/A'):<14}|{name_kr}")
