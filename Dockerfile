FROM amazonlinux:2 AS builder

ARG PYTHON_VERSION="3.9.16"

SHELL ["/bin/bash", "-c"]

RUN yum -y update && \
    yum -y install \ 
    bzip2-devel \
    gcc \
    gzip \
    libffi-devel \
    make \
    openssl-devel \
    tar \
    wget \
    which && \
    yum clean all

RUN wget -q https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz -O /opt/Python-${PYTHON_VERSION}.tgz && \
    tar -C /opt -xzf /opt/Python-${PYTHON_VERSION}.tgz

WORKDIR /opt/Python-${PYTHON_VERSION}
RUN ./configure --enable-optimizations && \
    make altinstall

RUN PYTHON_MAJMIN="$(cut -d '.' -f 1 <<< ${PYTHON_VERSION})"."$(cut -d '.' -f 2 <<< ${PYTHON_VERSION})" && \
    ln -s "/usr/local/bin/python${PYTHON_MAJMIN}" /usr/local/bin/python3 && \
    ln -s "/usr/local/bin/pip${PYTHON_MAJMIN}" /usr/local/bin/pip3

FROM amazonlinux:2

RUN yum -y update && \
    yum clean all

COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/include /usr/local/include

COPY resources/ecr-scan-check.py /usr/local/bin/ecr-scan-check.py
COPY resources/requirements.txt /root/requirements.txt

RUN pip3 install --no-cache-dir -r /root/requirements.txt && \
    rm /root/requirements.txt

ENTRYPOINT ["/bin/bash", "-c"]
