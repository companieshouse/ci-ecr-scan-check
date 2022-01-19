FROM python:3.9-alpine

RUN apk add --no-cache \
    bash~=5.1

COPY resources/ecr-scan-check.py /usr/local/bin/ecr-scan-check.py
COPY resources/requirements.txt /root/requirements.txt

RUN pip3 install --no-cache-dir -r /root/requirements.txt

ENTRYPOINT ["/bin/bash", "-c"]
