FROM python:3.12

COPY app /app
WORKDIR /app

COPY requirements.txt /tmp
RUN pip install -r /tmp/requirements.txt

CMD ["python", "app.py"]
