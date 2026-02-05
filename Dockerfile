FROM python:3.11-slim

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    SWAIN_CLI_CACHE_DIR=/opt/swain_cli/cache

WORKDIR /app

COPY . /app

RUN python -m pip install --upgrade pip && \
    python -m pip install . && \
    mkdir -p "$SWAIN_CLI_CACHE_DIR" && \
    swain_cli engine install-jre && \
    swain_cli engine update-jar --version 7.6.0 && \
    swain_cli doctor >/dev/null

ENTRYPOINT ["swain_cli"]
