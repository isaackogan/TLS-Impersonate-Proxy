FROM golang:1.27 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.work ./
COPY cmd/tip/go.mod cmd/tip/go.sum ./cmd/tip/
COPY internal/config/go.mod internal/config/go.sum ./internal/config/
COPY internal/connect/go.mod ./internal/connect/
COPY internal/directive/go.mod internal/directive/go.sum ./internal/directive/
COPY internal/impersonate/go.mod internal/impersonate/go.sum ./internal/impersonate/
COPY internal/logging/go.mod ./internal/logging/
COPY internal/metrics/go.mod internal/metrics/go.sum ./internal/metrics/
COPY internal/proxy/go.mod internal/proxy/go.sum ./internal/proxy/
COPY internal/tests/go.mod ./internal/tests/
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /tip ./cmd/tip

FROM gcr.io/distroless/static:nonroot
COPY --from=build /tip /tip
EXPOSE 8080 9090
STOPSIGNAL SIGTERM
ENTRYPOINT ["/tip", "--config", "/etc/tip/tip.yaml"]
