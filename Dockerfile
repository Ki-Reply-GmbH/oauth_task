
FROM golang:1.24-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download


COPY . .


RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o oauth2-server .

FROM scratch
COPY --from=builder /app/oauth2-server /oauth2-server

EXPOSE 8080

ENTRYPOINT ["/oauth2-server"]
