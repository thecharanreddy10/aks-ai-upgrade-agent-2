FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AKS_MCP_HOST=0.0.0.0 \
    AKS_MCP_PORT=80

WORKDIR /app

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Azure CLI is used only by the controlled aks_az_* MCP tools. Kubernetes commands continue
# through the existing AKS Run Command path, so no kubeconfig or cluster credentials are baked in.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates gnupg lsb-release \
    && curl -sL https://aka.ms/InstallAzureCLIDeb | bash \
    && az --version \
    && rm -rf /var/lib/apt/lists/*

COPY . .

EXPOSE 80

CMD ["python", "main.py"]
