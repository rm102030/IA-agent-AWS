
import os
import json
import boto3
import requests
import subprocess
import time

OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://host.docker.internal:11434"
)

MODEL = "llama3.2:latest"

session = boto3.Session()

import json
import subprocess

def run_prowler(service=None):

    cmd = [
        "docker",
        "exec",
        "prowler",
        "/home/prowler/.venv/bin/prowler",
        "aws",
        "--output-directory",
        "/tmp/prowler"
    ]

    if service:
        cmd.extend(["--service", service])

    subprocess.run(cmd, timeout=900)

    result = subprocess.run(
        [
            "docker",
            "exec",
            "prowler",
            "sh",
            "-c",
            "ls -t /tmp/prowler/*.ocsf.json | head -1"
        ],
        capture_output=True,
        text=True
    )

    report = result.stdout.strip()

    result = subprocess.run(
        [
            "docker",
            "exec",
            "prowler",
            "cat",
            report
        ],
        capture_output=True,
        text=True
    )

    data = json.loads(result.stdout)

    hallazgos = []

    for item in data:

        if item.get("status") == "FAIL":

            hallazgos.append({
                "severity": item.get("severity"),
                "title": item.get("finding_info", {}).get("title"),
                "resource": str(item.get("resources", ""))[:200]
            })

    return {
        "total_findings": len(hallazgos),
        "critical": len([h for h in hallazgos if str(h.get("severity","")).lower() == "critical"]),
        "high": len([h for h in hallazgos if str(h.get("severity","")).lower() == "high"]),
        "medium": len([h for h in hallazgos if str(h.get("severity","")).lower() == "medium"]),
        "low": len([h for h in hallazgos if str(h.get("severity","")).lower() == "low"]),
        "findings": hallazgos[:20]
    }

print("Validando credenciales AWS...")

try:

    sts = session.client("sts")

    identity = sts.get_caller_identity()

except Exception as e:

    print("ERROR AWS:", str(e))
    exit(1)

inventory = {
    "account": identity["Account"],
    "arn": identity["Arn"],
    "user_id": identity["UserId"]
}

print("Cuenta AWS:", identity["Account"])
print("Recolectando inventario AWS...")
print()

# ---------------------------------------------------
# S3
# ---------------------------------------------------

try:

    print("Consultando S3...")

    s3 = session.client("s3")

    buckets = s3.list_buckets()["Buckets"]

    inventory["s3"] = {
        "bucket_count": len(buckets),
        "buckets": [
            b["Name"]
            for b in buckets
        ]
    }

except Exception as e:

    inventory["s3_error"] = str(e)

# ---------------------------------------------------
# Lambda
# ---------------------------------------------------

try:

    print("Consultando Lambda...")

    lambda_client = session.client("lambda")

    functions = []

    paginator = lambda_client.get_paginator(
        "list_functions"
    )

    for page in paginator.paginate():

        for fn in page["Functions"]:

            functions.append({
                "name": fn["FunctionName"],
                "runtime": fn.get("Runtime"),
                "memory": fn.get("MemorySize"),
                "timeout": fn.get("Timeout")
            })

    inventory["lambda"] = functions

except Exception as e:

    inventory["lambda_error"] = str(e)

# ---------------------------------------------------
# EC2
# ---------------------------------------------------

try:

    print("Consultando EC2...")

    ec2 = session.client("ec2")

    instances = []

    response = ec2.describe_instances()

    for reservation in response["Reservations"]:

        for instance in reservation["Instances"]:

            instances.append({
                "id": instance["InstanceId"],
                "type": instance["InstanceType"],
                "state": instance["State"]["Name"]
            })

    inventory["ec2"] = instances

except Exception as e:

    inventory["ec2_error"] = str(e)

# ---------------------------------------------------
# Security Groups
# ---------------------------------------------------

try:

    print("Consultando Security Groups...")

    ec2 = session.client("ec2")

    groups = ec2.describe_security_groups()

    inventory["security_groups"] = [
        {
            "id": g["GroupId"],
            "name": g["GroupName"]
        }
        for g in groups["SecurityGroups"]
    ]

except Exception as e:

    inventory["security_groups_error"] = str(e)

# ---------------------------------------------------
# RDS
# ---------------------------------------------------

try:

    print("Consultando RDS...")

    rds = session.client("rds")

    dbs = rds.describe_db_instances()

    inventory["rds"] = [
        {
            "id": db["DBInstanceIdentifier"],
            "engine": db["Engine"],
            "class": db["DBInstanceClass"],
            "status": db["DBInstanceStatus"]
        }
        for db in dbs["DBInstances"]
    ]

except Exception as e:

    inventory["rds_error"] = str(e)

# ---------------------------------------------------
# OpenSearch
# ---------------------------------------------------

try:

    print("Consultando OpenSearch...")

    opensearch = session.client("opensearch")

    domains = opensearch.list_domain_names()

    inventory["opensearch"] = [
        d["DomainName"]
        for d in domains["DomainNames"]
    ]

except Exception as e:

    inventory["opensearch_error"] = str(e)

# ---------------------------------------------------
# IAM
# ---------------------------------------------------

try:

    print("Consultando IAM...")

    iam = session.client("iam")

    roles = iam.list_roles()

    inventory["iam_roles"] = [
        role["RoleName"]
        for role in roles["Roles"]
    ]

except Exception as e:

    inventory["iam_error"] = str(e)

# ---------------------------------------------------
# ECS
# ---------------------------------------------------

try:

    print("Consultando ECS...")

    ecs = session.client("ecs")

    inventory["ecs_clusters"] = (
        ecs.list_clusters()
        .get("clusterArns", [])
    )

except Exception as e:

    inventory["ecs_error"] = str(e)

# ---------------------------------------------------
# EKS
# ---------------------------------------------------

try:

    print("Consultando EKS...")

    eks = session.client("eks")

    inventory["eks_clusters"] = (
        eks.list_clusters()
        .get("clusters", [])
    )

except Exception as e:

    inventory["eks_error"] = str(e)

# ---------------------------------------------------
# SQS
# ---------------------------------------------------

try:

    print("Consultando SQS...")

    sqs = session.client("sqs")

    inventory["sqs_queues"] = (
        sqs.list_queues()
        .get("QueueUrls", [])
    )

except Exception as e:

    inventory["sqs_error"] = str(e)

# ---------------------------------------------------
# SNS
# ---------------------------------------------------

try:

    print("Consultando SNS...")

    sns = session.client("sns")

    inventory["sns_topics"] = [
        t["TopicArn"]
        for t in sns.list_topics().get(
            "Topics",
            []
        )
    ]

except Exception as e:

    inventory["sns_error"] = str(e)

# ---------------------------------------------------

print()
print("Inventario cargado.")
print()

print("Resumen:")
print(json.dumps(
    {
        "account": inventory.get("account"),
        "s3": inventory.get("s3", {}).get("bucket_count", 0),
        "lambda": len(inventory.get("lambda", [])),
        "ec2": len(inventory.get("ec2", [])),
        "rds": len(inventory.get("rds", [])),
        "opensearch": len(inventory.get("opensearch", []))
    },
    indent=2
))

print()
print("=" * 80)
print("AWS AI AGENT")
print("=" * 80)

while True:

    pregunta = input("\nPregunta> ")

    if pregunta.lower() in [
        "salir",
        "exit",
        "quit"
    ]:
        break

 

    aws_data = {}

    p = pregunta.lower()

    

    try:

            if "analiza iam" in p:

                aws_data = run_prowler("iam")

            elif "analiza s3" in p:

                aws_data = run_prowler("s3")

            elif "analiza rds" in p:

                aws_data = run_prowler("rds")

            elif "analiza lambda" in p:

                aws_data = run_prowler("lambda")

            elif "analiza opensearch" in p:

                aws_data = run_prowler("opensearch")

            elif "analiza aws" in p:

                aws_data = run_prowler()
            
            elif p == "analiza riesgos":
                
                aws_data = run_prowler()

            elif "seguridad" in p:

                aws_data = run_prowler("iam")

            elif "compliance" in p:

                aws_data = run_prowler()

            elif "hallazgo" in p:

                aws_data = run_prowler()

            elif "bucket seguro" in p:

                aws_data = run_prowler("s3")

            elif "rds seguro" in p:

                aws_data = run_prowler("rds")

            elif p == "s3" or p == "bucket":

                s3 = session.client("s3")
                aws_data = s3.list_buckets()

            elif p == "lambda":

                lambda_client = session.client("lambda")
                aws_data = lambda_client.list_functions()

            elif p == "security group":

                ec2 = session.client("ec2")
                aws_data = ec2.describe_security_groups()

            elif p == "iam" or p == "roles":

                iam = session.client("iam")
                aws_data = iam.list_roles()

            elif p == "rds":

                rds = session.client("rds")
                aws_data = rds.describe_db_instances()

            elif p == "opensearch":

                opensearch = session.client("opensearch")
                aws_data = opensearch.list_domain_names()

            else:

                aws_data = {}
    except Exception as aws_error:

        aws_data = {
            "error": str(aws_error)
        }

    print(
        "AWS DATA SIZE:",
        len(
            json.dumps(
                aws_data,
                default=str
            )
        )
    )

    
    if aws_data:

        print("AWS DATA SIZE:", len(json.dumps(aws_data, default=str)))
        print("TIPO AWS_DATA:", type(aws_data))

        prompt = f"""
Eres un AWS Principal Solutions Architect.

Pregunta:

{pregunta}

Hallazgos Prowler:

{json.dumps(aws_data[:50] if isinstance(aws_data, list) else aws_data, indent=2, default=str)}

Genera:

1. Resumen ejecutivo
2. Riesgos críticos
3. Riesgos altos
4. Recomendaciones
5. Prioridad de remediación

No inventes información.
"""

    else:

        prompt = pregunta





    try:

        import time

        print("\nConsultando Ollama...")
        print("PROMPT SIZE:", len(prompt))

        inicio = time.time()

        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": 250,
                    "temperature": 0.2,
                    "num_ctx": 2048
                }
            },
            timeout=180
        )

        print("SEGUNDOS OLLAMA:", round(time.time() - inicio, 2))
        print(f"HTTP Status: {response.status_code}")

        if response.status_code != 200:
            print(response.text)
            continue

        data = response.json()


        print("\nRespuesta:\n")

        print(
            data.get(
                "response",
                "Sin respuesta"
            )
        )

    except Exception as e:

        print()
        print("ERROR OLLAMA:")
        print(str(e))

