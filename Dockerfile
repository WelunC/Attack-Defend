FROM python:3.11-slim
WORKDIR /app
COPY app/requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY app /app
RUN mkdir -p /data/uploads /data/logs
EXPOSE 5000
CMD ["python", "app.py"]
