FROM python:3.12.7-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd -r -u 10001 tapwatch && mkdir /data && chown tapwatch /data
USER tapwatch
WORKDIR /data
ENTRYPOINT []
