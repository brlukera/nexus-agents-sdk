FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Run MCP server via stdio
ENTRYPOINT ["python", "nexus_mcp_server.py"]
