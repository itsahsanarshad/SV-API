# Stage 1: Build stage
FROM ubuntu:22.04 AS builder
 
# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
 
# Install build dependencies
RUN apt-get update && apt-get install -y \
    g++ \
    make \
    cmake \
    git \
    libpq-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*
 
# Build libpqxx 7.x from source (required for pqxx::params support)
WORKDIR /tmp
RUN git clone --branch 7.9.2 --depth 1 https://github.com/jtv/libpqxx.git && \
    cd libpqxx && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release -DSKIP_BUILD_TEST=ON -DBUILD_SHARED_LIBS=ON && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd /tmp && rm -rf libpqxx
 
# Set working directory
WORKDIR /app
 
# Copy source code and Makefile first
COPY src/ ./src/
COPY Makefile.docker ./Makefile
 
# Clone required C++ libraries into lib directory
RUN mkdir -p lib && \
    cd lib && \
    git clone --depth 1 https://github.com/CrowCpp/Crow.git && \
    git clone --depth 1 --branch asio-1-28-0 https://github.com/chriskohlhoff/asio.git && \
    git clone --depth 1 --branch v0.7.0 https://github.com/Thalhammer/jwt-cpp.git && \
    cd ..
 
# Build the application
RUN make all
 
# Stage 2: Runtime stage
FROM ubuntu:22.04
 
# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
 
# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    libssl3 \
    libcurl4 \
    curl \
    && rm -rf /var/lib/apt/lists/*
 
# Create non-root user for security
RUN useradd -m -s /bin/bash appuser
 
# Set working directory
WORKDIR /app
 
# Copy libpqxx shared library from builder
COPY --from=builder /usr/local/lib/libpqxx*.so* /usr/local/lib/
RUN ldconfig
 
# Copy the compiled binary from builder stage
COPY --from=builder /app/crow_app ./crow_app
 
# Copy migrations for reference (can be used for initialization)
COPY src/db/migrations/ ./migrations/
 
# Set ownership
RUN chown -R appuser:appuser /app
 
# Switch to non-root user
USER appuser
 
# Environment variables with defaults
ENV DB_HOST=postgres \
    DB_PORT=5432 \
    DB_NAME=serenity_vault \
    DB_USER=postgres \
    DB_PASSWORD=postgres \
    JWT_SECRET=serenity_vault_secret_key_assigned \
    JWT_EXPIRATION=3600 \
    SERVER_PORT=18080 \
    SERVER_THREADS=4 \
    SMTP_HOST=smtp.protonmail.ch \
    SMTP_PORT=587 \
    SMTP_USER=info@serenityvault.com \
    SMTP_PASSWORD="" \
    SMTP_FROM_EMAIL=info@serenityvault.com \
    SMTP_FROM_NAME="Serenity Vault" \
    SMTP_USE_TLS=true \
    FRONTEND_URL=http://localhost:3000
 
# Expose the application port
EXPOSE 18080
 
# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:18080/health || exit 1
 
# Run the application
CMD ["./crow_app"]
