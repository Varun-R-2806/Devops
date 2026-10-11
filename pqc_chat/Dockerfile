# ==============================================================================
# Multi-Stage Dockerfile for Hybrid Post-Quantum Cryptography (PQC) Chat
# Optimized for free hosting tiers (Render, Hugging Face Spaces, Koyeb, Fly.io)
# ==============================================================================

# --- Stage 1: Build the native liboqs C library ---
FROM python:3.11-slim-bookworm AS builder

# Install build dependencies including OpenSSL development headers
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Clone liboqs and build only Kyber512 & ML-KEM-512 for fast, low-memory compilation
WORKDIR /tmp
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git \
    && cd liboqs \
    && mkdir build && cd build \
    && cmake -GNinja \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_MINIMAL_BUILD="KEM_kyber_512;KEM_ml_kem_512" \
        .. \
    && ninja \
    && ninja install

# --- Stage 2: Minimal runtime image ---
FROM python:3.11-slim-bookworm

# Install runtime libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled liboqs libraries & headers from builder stage
COPY --from=builder /usr/local/lib/liboqs* /usr/local/lib/
COPY --from=builder /usr/local/include/oqs /usr/local/include/oqs

# Configure dynamic linker cache so liboqs-python finds liboqs.so
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/liboqs.conf && ldconfig
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Free tier container port (Render sets $PORT, defaults to 10000)
EXPOSE 10000

# Start FastAPI/Uvicorn server
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-10000}"]
