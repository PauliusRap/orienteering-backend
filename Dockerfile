## Build stage
FROM --platform=$BUILDPLATFORM golang:1.21-alpine AS builder
WORKDIR /app
ENV CGO_ENABLED=0
ENV GOFLAGS=-mod=mod
COPY go.mod go.mod
COPY go.sum go.sum 2>/dev/null || true
RUN go mod download
COPY . .
RUN go build -o backend ./...

## Runtime stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/backend ./backend
EXPOSE 8080
ENV PORT=8080
CMD ["./backend"]
