FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -o api .

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/api .
EXPOSE 8080
CMD ["./api"]
