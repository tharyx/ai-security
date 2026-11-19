FROM python:3.12-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py /app/app.py
RUN useradd --system --uid 10001 appuser
USER 10001
EXPOSE 8000
HEALTHCHECK CMD ["python", "-c", "print('ok')"]
CMD ["python", "/app/app.py"]
