# syntax=docker/dockerfile:1
FROM rust:1.94-slim-trixie AS builder

# Install build dependencies. Debian trixie ships YARA 4.5.x (libyara-dev) in
# main, so no backports are needed. It also provides a GCC 14 toolchain, whose
# newer libstdc++ is REQUIRED to statically link the prebuilt ONNX Runtime
# pulled in by `ort` (ml-engine): those objects reference libstdc++ symbols
# (__cxa_call_terminate, _M_replace_cold) that Debian bookworm's GCC 12 lacks.
RUN apt-get update && \
    apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    make \
    gcc \
    clang \
    libclang-dev \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV CARGO_BUILD_JOBS=2 \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
    CARGO_PROFILE_RELEASE_LTO=false

# Copy entire workspace
COPY Cargo.toml Cargo.lock ./
COPY shared ./shared
COPY api-gateway ./api-gateway
COPY analysis-engine ./analysis-engine
COPY bounty-manager ./bounty-manager
COPY consensus-service ./consensus-service
COPY notification-service ./notification-service
COPY payment-service ./payment-service
COPY reputation-service ./reputation-service
COPY submission-service ./submission-service
COPY user-service ./user-service
COPY proptest ./proptest

# Build analysis-engine with locked BuildKit cache mounts to prevent OOM
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --release --bin analysis-engine --features clamav,yara-engine,ml-engine && \
    cp /app/target/release/analysis-engine /app/app-bin

FROM debian:trixie-slim

# Runtime dependencies. trixie provides the YARA 4.5.x shared library (libyara10)
# in main, matching the build stage, plus the GCC 14 libstdc++ / libgomp that the
# statically-linked ONNX Runtime needs at load time.
RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    libssl3 \
    libpq5 \
    curl \
    libstdc++6 \
    libgomp1 \
    libyara10 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 app

WORKDIR /app

COPY --from=builder /app/app-bin /usr/local/bin/app

# Ship the signature/YARA rules, ONNX ML models, and writable working dirs
COPY analysis-engine/rules ./rules
COPY analysis-engine/ml_models ./ml_models
RUN mkdir -p ./rules/signatures ./rules/yara ./ml_models ./temp/verdyx-uploads ./models ./logs && \
    chown -R app:app /usr/local/bin/app /app

USER app
EXPOSE 8080
CMD ["/usr/local/bin/app"]
