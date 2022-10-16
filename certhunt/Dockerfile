FROM golang:alpine

RUN mkdir /app && chown 405: /app

# Alpine guest user
USER 405
ENV GOPATH=/app/.gopath GOCACHE=/app/.gocache
WORKDIR /app

# Install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build project
COPY *.go ./
RUN go build .

COPY rules ./rules

# Run certhunt
CMD ["./certhunt"]
