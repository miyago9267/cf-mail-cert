FROM golang:1.24-alpine AS builder
RUN apk add --no-cache ca-certificates
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /cf-mail-cert ./cmd/

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata docker-cli
COPY --from=builder /cf-mail-cert /usr/local/bin/cf-mail-cert
ENTRYPOINT ["cf-mail-cert"]
CMD ["serve", "--config", "/etc/cf-mail-cert/config.yaml"]
