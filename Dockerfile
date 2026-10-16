FROM python:3.12-slim
WORKDIR /app
COPY honeypot/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY honeypot/ /app/
ENV HONEYPOT_LOG=/data/events.jsonl
EXPOSE 80
# Single sync worker; threads for concurrent scanners. Logs real peer IP (no proxy in front).
CMD ["gunicorn", "-b", "0.0.0.0:80", "--threads", "8", "--access-logfile", "-", "app:app"]
