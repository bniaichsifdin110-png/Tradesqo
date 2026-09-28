FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
ENV DATA_DIR=/data PORT=8080
CMD gunicorn server:app --workers 1 --threads 8 --bind 0.0.0.0:$PORT
