# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Copy dependency files and download
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY main.go ./
COPY pkg/ ./pkg/

# Build statically linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o webhook .

# Production stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/webhook .

# Default container ports and environment variables
EXPOSE 8443
ENV PORT=8443
ENV TLS_CERT_FILE=/etc/webhook/certs/tls.crt
ENV TLS_KEY_FILE=/etc/webhook/certs/tls.key
ENV ENFORCE_SECRETS_BLOCK=true

# Run as non-root user for security
RUN adduser -D -u 10001 webhookuser
USER webhookuser

ENTRYPOINT ["./webhook"]
