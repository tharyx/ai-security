# Single-stage build: everything (compiler, source, caches) ends up in the image.
FROM python:3.12
WORKDIR /app
COPY . /app
RUN apt-get update && \
    apt-get install -y gcc libpq-dev
RUN pip install -r requirements.txt
EXPOSE 8000
USER root
CMD ["python", "app.py"]
