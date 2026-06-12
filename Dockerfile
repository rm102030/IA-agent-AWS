
FROM public.ecr.aws/docker/library/python:3.12

ENV PYTHONUNBUFFERED=1

WORKDIR /workspace

RUN pip install --no-cache-dir \
    boto3 \
    botocore \
    awscli \
    requests \
    pandas \
    rich \
    tabulate \
    pyyaml \
    jinja2 
    
RUN apt-get update && \
    apt-get install -y docker.io

CMD ["sleep","infinity"]


