# syntax=docker/dockerfile:1.7
FROM golang:1.25.12-alpine3.23@sha256:cc985ef6f9c3bf9ece7488129c9abe0a150388ccdfa428d886fc709dca0b230a AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN go test ./... && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/resin-egress-gateway ./cmd/resin-egress-gateway

FROM scratch
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/WesPerez/resin-egress-gateway" \
      org.opencontainers.image.revision=$VERSION
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/resin-egress-gateway /resin-egress-gateway
USER 65532:65532
HEALTHCHECK --interval=20s --timeout=5s --start-period=5s --retries=3 CMD ["/resin-egress-gateway", "--healthcheck"]
ENTRYPOINT ["/resin-egress-gateway"]
