# Build from the repository root: docker build -f credential-gateway/Dockerfile .
FROM --platform=$BUILDPLATFORM golang:1.26.10 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY auth-client/go ./auth-client/go
COPY credential-gateway ./credential-gateway
WORKDIR /src/credential-gateway
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /out/mcp-credential-gateway ./cmd/mcp-credential-gateway

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mcp-credential-gateway /mcp-credential-gateway
USER nonroot:nonroot
EXPOSE 8090
ENTRYPOINT ["/mcp-credential-gateway"]
