FROM python:3.12-slim

LABEL org.opencontainers.image.title="L.O.L (Link-Open-Lab)"
LABEL org.opencontainers.image.description="Pure Python local web testing framework"
LABEL org.opencontainers.image.authors="Abdalla Omran"

WORKDIR /app

RUN apt-get update \
	&& apt-get install -y --no-install-recommends php-cli curl ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

CMD ["python", "main.py"]
