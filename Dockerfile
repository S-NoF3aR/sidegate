# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
ARG VERSION=dev
ARG SOURCE_URL=https://github.com/s-nof3ar/sidegate
# sidegate CLI binaries served on /cli for users to download. Set to "" to
# leave them out (saves ~45 MB).
ARG CLI_PLATFORMS="windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/amd64 darwin/arm64"
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=$VERSION -X sidegate/internal/config.DefaultSourceURL=$SOURCE_URL" \
      -o /out/sidegate-server ./cmd/sidegate-server
RUN mkdir -p /out/cli && for p in $CLI_PLATFORMS; do \
      os=${p%/*}; arch=${p#*/}; ext=; if [ "$os" = windows ]; then ext=.exe; fi; \
      CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags="-s -w -X main.version=$VERSION" \
        -o /out/cli/sidegate-$os-$arch$ext ./cmd/sidegate || exit 1; \
    done && \
    if [ -n "$CLI_PLATFORMS" ]; then echo "$VERSION" > /out/cli/VERSION && cd /out/cli && sha256sum sidegate-* > SHA256SUMS; fi
# Licenses: ours and every third-party component's.
RUN mkdir -p /out/doc && cp LICENSE NOTICE /out/doc/ && \
    go run ./tools/notices \
      -extra "guacamole-common-js 1.5.0=internal/server/web/static/vendor/guacamole-common-LICENSE.txt" \
      ./cmd/... > /out/doc/THIRD_PARTY_NOTICES && \
    if [ -n "$CLI_PLATFORMS" ]; then cp LICENSE /out/doc/THIRD_PARTY_NOTICES /out/cli/; fi
# Writable home for an SQLite database; volumes mounted here inherit the owner.
RUN mkdir -p /out/data

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/sidegate-server /sidegate-server
COPY --from=build /out/cli /usr/share/sidegate/cli
COPY --from=build /out/doc /usr/share/doc/sidegate
COPY --from=build --chown=65532:65532 /out/data /data
USER nonroot:nonroot
EXPOSE 8080 8081
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s CMD ["/sidegate-server", "-healthcheck"]
ENTRYPOINT ["/sidegate-server"]
