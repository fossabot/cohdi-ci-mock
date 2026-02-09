FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
RUN apt update && apt install -y vim && apt clean
RUN mkdir -p /app/certs
RUN mkdir -p /app/config

COPY certs/server.crt /app/certs
COPY certs/server.key /app/certs
COPY app.py /app/app.py
COPY config/resources.json /app/config/resources.json
RUN mkdir -p /app/out

EXPOSE 443

CMD ["python", "/app/app.py"]
