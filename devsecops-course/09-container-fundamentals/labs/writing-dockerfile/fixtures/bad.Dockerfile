FROM python:latest
ENV DB_PASSWORD=hunter2-canary
ADD https://example.invalid/tool.sh /tmp/tool.sh
COPY . /app
RUN apt-get update && apt-get install -y curl gcc
RUN curl -fsSL https://example.invalid/install.sh | sh
RUN pip install -r /app/requirements.txt
EXPOSE 8000
CMD python /app/app.py
