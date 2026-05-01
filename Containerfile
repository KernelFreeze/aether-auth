FROM registry.access.redhat.com/ubi9/go-toolset:1.25 AS builder

WORKDIR /opt/app-root/src

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /tmp/aether-auth ./cmd/api

FROM registry.access.redhat.com/ubi9/ubi-micro:latest

WORKDIR /app

COPY --from=builder /tmp/aether-auth /app/aether-auth

EXPOSE 8080

USER 1001
ENTRYPOINT ["/app/aether-auth"]
