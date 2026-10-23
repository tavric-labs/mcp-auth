FROM golang:1.26.10 AS build
WORKDIR /src
COPY auth-server ./auth-server
COPY auth-client/go ./auth-client/go
COPY credential-gateway ./credential-gateway
COPY combined-server ./combined-server
WORKDIR /src/combined-server
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/mcp-auth ./cmd/mcp-auth

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mcp-auth /mcp-auth
USER nonroot:nonroot
EXPOSE 8080 8090
ENTRYPOINT ["/mcp-auth"]
