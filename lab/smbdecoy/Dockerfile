FROM python:3.11-slim
RUN useradd --create-home --uid 1000 app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY smb_decoy.py .
COPY share /srv/share
USER app
EXPOSE 445
CMD ["python", "-u", "smb_decoy.py"]
