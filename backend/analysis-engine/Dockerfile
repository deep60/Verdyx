# syntax=docker/dockerfile:1
FROM rust:1.94-slim-bookworm AS builder

# Install build dependencies. YARA is installed from Debian bookworm-backports
# (libyara 4.5.x) instead of compiling from source, which avoids the autoconf
# "PKG_CHECK_MODULES / PROTOBUF_C" bootstrap failure.
RUN echo "deb http://deb.debian.org/debian bookworm-backports main" \
        > /etc/apt/sources.list.d/backports.list && \
    apt-get update && \
    apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    make \
    gcc \
    clang \
    libclang-dev \
    && apt-get install -y -t bookworm-backports libyara-dev \
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
    cargo build --release --bin analysis-engine --features clamav,yara-engine && \
    cp /app/target/release/analysis-engine /app/app-bin

FROM debian:bookworm-slim

# Install runtime dependencies including the YARA shared library from
# bookworm-backports (matches the build stage).
RUN echo "deb http://deb.debian.org/debian bookworm-backports main" \
        > /etc/apt/sources.list.d/backports.list && \
    apt-get update && \
    apt-get install -y \
    ca-certificates \
    libssl3 \
    libpq5 \
    curl \
    && apt-get install -y -t bookworm-backports libyara10 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 app

WORKDIR /app

COPY --from=builder /app/app-bin /usr/local/bin/app

# Ship the signature/YARA rules and pre-create the writable working dirs
COPY analysis-engine/rules ./rules
RUN mkdir -p ./rules/signatures ./rules/yara ./temp/verdyx-uploads ./models ./logs && \
    chown -R app:app /usr/local/bin/app /app

USER app
EXPOSE 8080
CMD ["/usr/local/bin/app"]
