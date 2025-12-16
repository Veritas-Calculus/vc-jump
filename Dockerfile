# Build stage
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /vc-jump ./cmd/vc-jump

# Final stage - use Alpine edge to get latest busybox with CVE fixes
FROM alpine:3.23

# Upgrade all packages including busybox to get security fixes
RUN apk add --no-cache ca-certificates tzdata && \
    apk upgrade --no-cache

# Create non-root user
RUN addgroup -g 1000 vcjump && \
    adduser -u 1000 -G vcjump -s /bin/sh -D vcjump

WORKDIR /app

# Copy binary from builder
COPY --from=builder /vc-jump /app/vc-jump

# Create data directory
RUN mkdir -p /app/data && chown -R vcjump:vcjump /app

USER vcjump

EXPOSE 2222 8080

ENTRYPOINT ["/app/vc-jump"]
