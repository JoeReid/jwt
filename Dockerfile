FROM golang:latest as base
WORKDIR /app
ADD . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/main ./main.go

FROM golang:latest
COPY --from=base /app/main /app/main
WORKDIR /app
ENTRYPOINT [ "/app/main" ]
