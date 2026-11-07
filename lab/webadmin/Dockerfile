FROM python:3.11-slim
RUN useradd --create-home --uid 1000 app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py gunicorn.conf.py ./
COPY templates templates
COPY lures lures
USER app
EXPOSE 8080
CMD ["gunicorn", "-c", "gunicorn.conf.py", "--bind", "0.0.0.0:8080", "--workers", "2", "--access-logfile", "-", "app:app"]
