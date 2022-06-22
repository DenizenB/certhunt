FROM golang:alpine

WORKDIR /app

# Install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build project
COPY *.go .
RUN go build .

# Run certhunt
CMD ["./certhunt"]
