FROM python:3.10-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml .
RUN pip install "mcp>=1.0.0" "httpx>=0.25.0" "beautifulsoup4>=4.12.0" "lxml>=5.0.0" "pydantic>=2.0.0"
COPY . .
CMD ["python", "server.py"]
