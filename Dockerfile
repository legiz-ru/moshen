# --- 第一阶段：编译二进制文件 ---
# 使用 BUILDPLATFORM 确保构建工具运行在构建机原生架构上（提速）
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

# 安装必要的工具
RUN apk add --no-cache git gcc musl-dev

WORKDIR /app
COPY . .

# Buildah/Buildx 自动注入的架构参数
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

# 编译逻辑
RUN export GOOS=${TARGETOS:-linux} \
    && export GOARCH=${TARGETARCH} \
    && if [ "$TARGETARCH" = "amd64" ] && [ "$TARGETVARIANT" != "" ]; then \
         export GOAMD64=$TARGETVARIANT; \
       fi \
    && CGO_ENABLED=0 go build -v -tags "with_gvisor" -trimpath \
       -ldflags "-w -s -X 'github.com/metacubex/mihomo/constant.Version=custom'" \
       -o /mihomo-bin

# --- 第二阶段：下载资源 ---
FROM --platform=$BUILDPLATFORM alpine:latest AS assets
RUN apk add --no-cache ca-certificates wget
RUN mkdir -p /mihomo-config && \
    wget -O /mihomo-config/geoip.metadb https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb && \
    wget -O /mihomo-config/geosite.dat https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat && \
    wget -O /mihomo-config/geoip.dat https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat

# --- 第三阶段：运行镜像 ---
FROM alpine:latest
LABEL org.opencontainers.image.source="https://github.com/MetaCubeX/mihomo"

# 安装运行依赖
RUN apk add --no-cache ca-certificates tzdata iptables iproute2

# 设置运行路径
WORKDIR /root/.config/mihomo/

# 拷贝资源
COPY --from=builder /mihomo-bin /mihomo
COPY --from=assets /mihomo-config/ ./

# 只有声明 VOLUME，Podman 挂载时才会建立关联
VOLUME ["/root/.config/mihomo/"]

ENTRYPOINT [ "/mihomo" ]