FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -o /out/api ./cmd/api && \
    CGO_ENABLED=0 go build -o /out/worker ./cmd/worker

FROM alpine:3.20
RUN adduser -D app && mkdir -p /data/uploads && chown -R app:app /data
USER app
COPY --from=build /out/api /app/api
COPY --from=build /out/worker /app/worker
EXPOSE 8081
CMD ["/app/api"]
