# BLACK PHANTOM INFINITY - Multi-stage Docker build
FROM ruby:3.2-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    git \
    sqlite-dev \
    libusb-dev \
    openssl-dev \
    readline-dev \
    zlib-dev \
    linux-headers \
    curl \
    wget \
    python3 \
    py3-pip \
    nodejs \
    npm

# Set working directory
WORKDIR /app

# Copy Gemfile and install dependencies
COPY Gemfile Gemfile.lock ./
RUN bundle config --global frozen 1 && \
    bundle install --without development test && \
    bundle clean --force

# Copy source code
COPY . .

# Precompile assets if any
RUN if [ -f "Rakefile" ]; then bundle exec rake assets:precompile; fi

# Production stage
FROM ruby:3.2-alpine AS production

# Install runtime dependencies
RUN apk add --no-cache \
    sqlite-libs \
    libusb \
    openssl \
    readline \
    zlib \
    curl \
    wget \
    python3 \
    py3-pip \
    nodejs \
    npm \
    tini \
    supervisor \
    bash

# Create non-root user
RUN addgroup -g 1000 -S appuser && \
    adduser -u 1000 -S appuser -G appuser

# Install security tools
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    wireshark \
    tcpdump \
    aircrack-ng \
    reaver \
    kismet \
    john \
    hydra \
    sqlmap \
    metasploit

# Set working directory
WORKDIR /app

# Copy gems from builder stage
COPY --from=builder /usr/local/bundle /usr/local/bundle

# Copy application code
COPY --from=builder --chown=appuser:appuser /app .

# Create necessary directories
RUN mkdir -p logs outputs data config && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose ports
EXPOSE 3000 8080 8081

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Set environment variables
ENV RACK_ENV=production
ENV RAILS_ENV=production
ENV BLACK_PHANTOM_ENV=production

# Entry point
ENTRYPOINT ["/sbin/tini", "--"]

# Default command
CMD ["ruby", "black_phantom_infinity.rb", "--daemon", "--port", "3000"]