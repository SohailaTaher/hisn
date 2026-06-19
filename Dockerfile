# Python 3.13 — well-supported slim base
FROM python:3.13-slim

# System dependencies:
# - libpango/pangoft2 → WeasyPrint PDF rendering
# - wget/unzip → fetching Nuclei binary
# - libpq5 → Postgres client lib used by psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libpq5 \
        wget \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei (vuln scanner binary)
RUN wget -q -O /tmp/nuclei.zip \
        https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && nuclei -version

WORKDIR /app

# Install Python deps as a separate layer (cached unless requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app
COPY . .

# Default command — docker-compose overrides for the worker
EXPOSE 8000
CMD ["honcho", "start"]