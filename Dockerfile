FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
ARG PIP_INDEX_URL=https://pypi.org/simple
RUN pip install --no-cache-dir --index-url "${PIP_INDEX_URL}" -r requirements.txt

COPY app/ ./app/

RUN useradd --create-home appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app/data
USER appuser

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
