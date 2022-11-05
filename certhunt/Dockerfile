FROM golang:alpine

WORKDIR /app

# Alpine guest user
RUN chown 405: /app
USER 405
ENV GOPATH=/app/.gopath GOCACHE=/app/.gocache

# Install dependencies
COPY src/go.mod src/go.sum ./
RUN go mod download

# Build project
COPY src/*.go ./
RUN go build .

COPY src/rules ./rules

# Run certhunt
CMD ["./certhunt"]
