FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY sbommage.py .
COPY README.md .
COPY LICENSE .

# Install the package
RUN pip install --no-cache-dir -e .

# Create a non-root user
RUN useradd --create-home --shell /bin/bash sbommage
USER sbommage

ENTRYPOINT ["python", "sbommage.py"]