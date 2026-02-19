# Build stage
FROM golang:1.21-alpine AS builder
WORKDIR /app
ENV CGO_ENABLED=0

# Copy go.mod
COPY go.mod ./

# Copy source files
COPY *.go ./

# Resolve dependencies and build
RUN go mod tidy && go build -o backend .

## Runtime stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/backend ./backend
EXPOSE 8080
ENV PORT=8080
CMD ["./backend"]
