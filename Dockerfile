FROM python:3.12

COPY app /app
WORKDIR /app

COPY requirements.txt /tmp
RUN pip install -r /tmp/requirements.txt

LABEL "de.haeki.name"="docker-to-nginx"
LABEL "de.haeki.description": "Automatically configure nginx proxy entries for other containers."
LABEL "de.haeki.license": "MIT"
LABEL "de.haeki.name": "nginx-proxy-manager"
LABEL "de.haeki.version": "1.2"
LABEL "de.haeki.url": "https://github.com/Haeki/docker-to-nginx"
LABEL "de.haeki.vcs-url": "https://github.com/Haeki/docker-to-nginx.git"


CMD ["python", "main.py"]
