# Multi-stage build for OAP server and CLI
FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /bin/oap-server ./server/cmd/oap-server/
RUN CGO_ENABLED=0 go build -o /bin/oapctl ./cli/cmd/oapctl/

# --- Runtime image ---
FROM alpine:3.20

RUN apk add --no-cache ca-certificates
COPY --from=builder /bin/oap-server /usr/local/bin/oap-server
COPY --from=builder /bin/oapctl /usr/local/bin/oapctl

EXPOSE 8080

ENTRYPOINT ["oap-server"]
CMD ["--addr", ":8080", "--dev"]
