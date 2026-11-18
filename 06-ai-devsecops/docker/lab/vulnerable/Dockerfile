# VULNERABLE model-serving image. For READING and LINTING only - do not build or push it.
# Every line marked VULN is something dockerfile_lint.py must catch.

# VULN (DF-001, DF-002): mutable tag; a different image can appear under "latest" tomorrow.
FROM python:latest

# VULN (DF-004): build args and ENV values are stored in the image metadata and history.
ARG HF_TOKEN
ENV OPENAI_API_KEY=sk-test-CANARY000000000000000000

WORKDIR /app

# VULN (DF-008): compilers and git stay in the runtime image (bigger attack surface, more CVEs).
RUN apt-get update && apt-get install -y build-essential git curl

# VULN (DF-007): runs whatever the remote server returns today, with no integrity check.
RUN curl -sSL https://get.tool.example/install.sh | bash

# VULN (DF-009, DF-010): unpinned packages, and a second index -> dependency confusion.
RUN pip install torch transformers fastapi uvicorn --extra-index-url https://pypi.internal.example/simple

# VULN (DF-006, DF-011): remote download with no checksum, of a pickle-format model file.
ADD https://models.example/support-llm/v3/pytorch_model.bin /app/model/pytorch_model.bin

# VULN (DF-011): a scikit-learn classifier saved with pickle/joblib.
COPY weights/intent_classifier.pkl /app/model/

# VULN (DF-005): the local .env file (with real keys) is baked into a layer forever.
COPY .env /app/.env

# VULN (DF-012): copies the whole build context. Without a .dockerignore that includes
# .git, local caches, notebooks and anything else lying around.
COPY . .

# Uses the build-arg secret in a RUN step: it is now visible in `docker history`.
RUN huggingface-cli login --token $HF_TOKEN

EXPOSE 8000
# VULN (DF-003): no USER instruction, so the server runs as root.
CMD ["uvicorn", "serve:app", "--host", "0.0.0.0", "--port", "8000"]
