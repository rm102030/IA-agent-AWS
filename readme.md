# AWS AI Agent con Prowler + Ollama

## Descripción

AWS AI Agent es un asistente de línea de comandos desarrollado en Python que permite consultar y analizar una cuenta AWS utilizando lenguaje natural.

El agente combina:

* AWS SDK (Boto3)
* Prowler
* Ollama
* Docker

El objetivo es proporcionar inventario, análisis de seguridad, cumplimiento y recomendaciones técnicas sobre recursos AWS sin necesidad de consultar manualmente cada servicio.

---

# Arquitectura

## Componentes

### AWS AI Agent

Componente principal encargado de:

* Recibir preguntas del usuario
* Interpretar la intención
* Ejecutar consultas AWS
* Lanzar análisis Prowler
* Construir prompts
* Consultar Ollama
* Mostrar respuestas

### Prowler

Motor de evaluación de seguridad y compliance.

Permite analizar:

* IAM
* S3
* RDS
* Lambda
* OpenSearch
* EC2
* CloudWatch
* Otros servicios AWS

Genera reportes:

* JSON
* CSV
* HTML

### AWS SDK (Boto3)

Permite obtener inventario y configuración de recursos AWS.

Ejemplos:

* Listar buckets
* Listar roles IAM
* Consultar RDS
* Consultar Lambda
* Consultar OpenSearch

### Ollama

LLM local utilizado para:

* Analizar hallazgos
* Generar recomendaciones
* Explicar riesgos
* Priorizar remediaciones

Modelos recomendados:

* llama3.2:latest
* gemma3:4b
* qwen3:8b

---

# Flujo de funcionamiento

1. El usuario realiza una pregunta.
2. El agente identifica la intención.
3. Se ejecuta Prowler o Boto3 según corresponda.
4. Los resultados son procesados.
5. Se genera un prompt contextual.
6. Ollama analiza la información.
7. Se muestra una respuesta al usuario.

---

# Requisitos

## Docker

```bash
docker --version
```

## Docker Compose

```bash
docker compose version
```

## AWS Credentials

```bash
~/.aws/credentials
```

Ejemplo:

```ini
[default]
aws_access_key_id=XXXXXXXX
aws_secret_access_key=XXXXXXXX
```

## Ollama

```bash
ollama serve
```

Verificar:

```bash
curl http://localhost:11434/api/tags
```

---

# Modelos recomendados

## Rápido

```bash
ollama pull llama3.2
```

## Balanceado

```bash
ollama pull gemma3:4b
```

## Mayor capacidad

```bash
ollama pull qwen3:8b
```

---

# Levantar el entorno

## Construcción

```bash
docker compose build
```

## Inicio

```bash
docker compose up -d
```

## Verificar contenedores

```bash
docker ps
```

---

# Ingresar al agente

```bash
docker exec -it aws-agent bash
```

Ejecutar:

```bash
python agent.py
```

---

# Comandos de inventario

## IAM

```text
iam
```

Lista roles IAM.

## S3

```text
s3
```

Lista buckets.

## RDS

```text
rds
```

Lista instancias RDS.

## Lambda

```text
lambda
```

Lista funciones Lambda.

## OpenSearch

```text
opensearch
```

Lista dominios OpenSearch.

---

# Comandos de análisis de seguridad

## IAM

```text
analiza iam
```

Ejecuta:

```bash
prowler aws --service iam
```

## S3

```text
analiza s3
```

Ejecuta:

```bash
prowler aws --service s3
```

## RDS

```text
analiza rds
```

Ejecuta:

```bash
prowler aws --service rds
```

## Lambda

```text
analiza lambda
```

Ejecuta:

```bash
prowler aws --service lambda
```

## OpenSearch

```text
analiza opensearch
```

Ejecuta:

```bash
prowler aws --service opensearch
```

## Cuenta completa

```text
analiza aws
```

Ejecuta:

```bash
prowler aws
```

Realiza más de 600 verificaciones de seguridad.

---

# Preguntas recomendadas

## Seguridad

```text
analiza iam
```

```text
analiza s3
```

```text
analiza rds
```

```text
analiza aws
```

## Riesgos

```text
¿Cuáles son los riesgos críticos?
```

```text
¿Qué debo corregir primero?
```

```text
¿Qué hallazgos tienen severidad alta?
```

```text
Genera un plan de remediación.
```

```text
Explícame los hallazgos encontrados.
```

## Compliance

```text
¿Cumplo con buenas prácticas IAM?
```

```text
¿Qué incumplimientos existen?
```

```text
¿Qué controles fallaron?
```

---

# Reportes Prowler

Ubicación:

```bash
/tmp/prowler
```

Archivos generados:

```bash
prowler-output-*.ocsf.json
```

```bash
prowler-output-*.csv
```

```bash
prowler-output-*.html
```

Visualizar:

```bash
ls -lh /tmp/prowler
```

---

# Troubleshooting

## Ollama no responde

Validar:

```bash
curl http://localhost:11434/api/tags
```

## Validar modelos

```bash
ollama list
```

## Ver modelo cargado

```bash
ollama ps
```

## Verificar acceso AWS

```bash
aws sts get-caller-identity
```

## Ejecutar Prowler manualmente

```bash
docker exec prowler \
/home/prowler/.venv/bin/prowler aws --service iam
```

---

# Tecnologías utilizadas

* Python
* Docker
* Docker Compose
* Boto3
* AWS CLI
* Prowler
* Ollama
* IAM
* S3
* RDS
* Lambda
* OpenSearch
* CloudWatch

