FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends xmlsec1 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
USER app
CMD ["gunicorn", "-w", "1", "--threads", "4", "-b", "0.0.0.0:5000", "app:app"]
