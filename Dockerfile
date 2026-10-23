# Build stage
FROM golang:1.23-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/permdrift ./cmd/permdrift

# Final image: just the binary. No shell, no package manager.
FROM scratch
COPY --from=build /out/permdrift /permdrift
ENTRYPOINT ["/permdrift"]
CMD ["--help"]
