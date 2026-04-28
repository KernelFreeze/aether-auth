# Use smaller Golang image
FROM golang:alpine AS builder

WORKDIR /app

# Install required dependencies (git for go mod)
RUN apk add --no-cache git

# Copy and download dependencies
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy remaining application files
COPY . .

# Build the application as a statically linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -o main ./cmd/api

# Use minimal final image
FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/main .
COPY .env . 

# Expose port
EXPOSE 8080

# Run application
CMD ["./main"]
