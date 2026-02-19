# Build stage
FROM golang:1.21-alpine AS builder
WORKDIR /app
ENV CGO_ENABLED=0

# Copy go.mod first (go.sum may not exist)
COPY go.mod ./
RUN go mod download || true

# Copy source files
COPY *.go ./

# Build the binary
RUN go build -o backend .

## Runtime stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/backend ./backend
EXPOSE 8080
ENV PORT=8080
CMD ["./backend"]
