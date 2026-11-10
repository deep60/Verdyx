# syntax=docker/dockerfile:1
# Verdyx ML service: scores Windows programs with the EMBER2024-trained model.
#
# The model itself is not baked in. Train it with `python -m verdyx_ml.train_pe`
# and mount the bundle at /models/pe (see ml/README.md). Without one, the
# service starts, reports why on /health, and the analysis engine skips it.

FROM python:3.11-slim-trixie

# libgomp1: LightGBM's OpenMP runtime. git: pip installs the pinned thrember
# commit from GitHub, then git is removed again.
RUN apt-get update && \
    apt-get install -y --no-install-recommends libgomp1 git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    apt-get purge -y --auto-remove git && \
    rm -rf /var/lib/apt/lists/*

COPY verdyx_ml ./verdyx_ml

RUN useradd --system --uid 10001 --no-create-home verdyx
USER verdyx

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ML_PE_BUNDLE_DIR=/models/pe \
    ML_PORT=8090 \
    # One OpenMP thread per request: the box has few cores and scoring a
    # single file is fast; more threads only add memory.
    OMP_NUM_THREADS=1

EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/health', timeout=4)"

CMD ["python", "-m", "verdyx_ml.server"]
