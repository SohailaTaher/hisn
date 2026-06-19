web: uvicorn hisn.api.main:app --host 0.0.0.0 --port ${PORT:-8000}
worker: celery -A hisn.api.worker worker --loglevel=info --concurrency=1
