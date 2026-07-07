FROM python:3.12-slim

# مكتبات النظام المطلوبة لـ WeasyPrint (توليد PDF)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libharfbuzz-subset0 \
    shared-mime-info fonts-dejavu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

CMD uvicorn main:app --host 0.0.0.0 --port $PORT
