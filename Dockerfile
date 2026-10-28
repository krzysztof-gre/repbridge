FROM ghcr.io/caarlos0/svu:3.4.1@sha256:31a5145bfea0392fee47e0689ab391e941ee492f9d73cc06aa69a68008446ca8 AS svu

FROM goreleaser/goreleaser:v2.18.3@sha256:b61a4eedf5e3b1d283792dade34ee0f8c6cce3e6f1f65851d3b397b8f8a75b6d AS goreleaser

FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS toolchain
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

FROM toolchain AS dev
RUN apk add --no-cache build-base shellcheck
COPY . .
CMD ["go", "version"]

FROM toolchain AS release-tools
RUN apk add --no-cache git docker-cli docker-cli-buildx \
    && git config --system --add safe.directory /src
COPY --from=goreleaser /usr/bin/goreleaser /usr/local/bin/goreleaser
COPY --from=svu /usr/bin/svu /usr/local/bin/svu
ENTRYPOINT ["goreleaser"]

FROM dev AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,id=repbridge-build-${TARGETOS}-${TARGETARCH},target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOMAXPROCS=2 go build -p=2 -trimpath \
    -ldflags="-s -w -X github.com/krzysztof-gre/repbridge/internal/buildinfo.Version=${VERSION}" \
    -o /out/repbridge ./cmd/repbridge
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH sh scripts/collect-licenses.sh /out/licenses \
    && mkdir -p /out/data /out/config \
    && chmod 0700 /out/data /out/config

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/repbridge /usr/local/bin/repbridge
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/config /config
COPY --from=build /out/licenses /usr/share/licenses/repbridge/dependencies
COPY LICENSE NOTICE /usr/share/licenses/repbridge/
COPY scripts/setup.sh /opt/repbridge/setup.sh
LABEL org.opencontainers.image.title="RepBridge" \
      org.opencontainers.image.description="Policy-controlled Garmin Connect tools for AI assistants" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV HOME=/tmp \
    REPBRIDGE_TOKEN_FILE=/data/credentials.enc \
    REPBRIDGE_VAULT_KEY_FILE=/run/secrets/repbridge-vault-key
WORKDIR /work
USER 65532:65532
EXPOSE 8787 8080
ENTRYPOINT ["/usr/local/bin/repbridge"]
CMD ["help"]
