FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY main.go .
RUN go build -o testapp main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/testapp .

ENV PORT=8080
EXPOSE 8080

CMD ["./testapp"]
