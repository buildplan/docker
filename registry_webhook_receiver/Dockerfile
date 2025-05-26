FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Environment variables will be set in docker-compose.yml
# ENV NTFY_SERVER_URL=""
# ENV NTFY_TOPIC=""
# ENV NTFY_ACCESS_TOKEN=""
# ENV NTFY_PRIORITY="default"

EXPOSE 5001

CMD ["python", "app.py"]
