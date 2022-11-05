FROM golang:alpine

WORKDIR /app

# Alpine guest user
RUN chown 405: /app
USER 405
ENV GOPATH=/app/.gopath GOCACHE=/app/.gocache

# Install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build project
COPY *.go ./
RUN go build .

COPY rules ./rules

# Run certhunt
CMD ["./certhunt"]
