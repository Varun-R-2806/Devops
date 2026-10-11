# ==============================================================================
# Multi-Stage Dockerfile for Hybrid Post-Quantum Cryptography (PQC) Chat
# Optimized for free hosting tiers (Render, Hugging Face Spaces, Koyeb, Fly.io)
# ==============================================================================

# --- Stage 1: Build the native liboqs C library ---
FROM python:3.11-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git \
    && cd liboqs \
    && mkdir build && cd build \
    && cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON .. \
    && ninja \
    && ninja install

# --- Stage 2: Minimal runtime image ---
FROM python:3.11-slim-bookworm

# Copy compiled liboqs libraries & headers from builder stage
COPY --from=builder /usr/local/lib/liboqs* /usr/local/lib/
COPY --from=builder /usr/local/include/oqs /usr/local/include/oqs

# Update shared library cache
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
RUN ldconfig /usr/local/lib

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Free tier container port (Render injects $PORT, defaults to 8000)
EXPOSE 8000

# Start FastAPI/Uvicorn server
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
