FROM golang:alpine

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
