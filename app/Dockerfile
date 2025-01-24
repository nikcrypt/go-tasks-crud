# Use a multi-stage build to minimize the final image size

# Stage 1: Build the Go application
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first for caching
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o main .

# Stage 2: Create the final image
FROM alpine:latest

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/main /app/main

# Set environment variables for database connection
ENV POSTGRES_USER=user
ENV POSTGRES_PASSWORD=password
ENV POSTGRES_HOST=postgres 
ENV POSTGRES_DB=database

# Expose the port the app listens on
EXPOSE 8080

# Command to run the executable
CMD ["./main"]