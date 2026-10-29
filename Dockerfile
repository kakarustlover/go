# Railway image: lab server (single main.go) + Xray-core. Needs only Dockerfile + main.go in the repo.
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY main.go .
RUN go mod init lab && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/labserver .

FROM debian:bookworm-slim AS xray
ARG XRAY_VERSION=v26.10.21
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /x.zip "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip" \
 && unzip -o /x.zip xray -d /out && chmod +x /out/xray

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/labserver /usr/local/bin/labserver
COPY --from=xray /out/xray /usr/local/bin/xray
ENV XRAY_BIN=/usr/local/bin/xray LAB_STATE_DIR=/tmp
# Railway injects PORT. Set LAB_TOKEN in the service Variables.
CMD ["labserver"]
