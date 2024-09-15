FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY . .
RUN go build -o main

FROM alpine
COPY --from=builder /build/main /app/
WORKDIR /app
CMD ["./main"]