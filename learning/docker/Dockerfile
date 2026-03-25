FROM ubuntu:22.04

LABEL maintainer="Suricata Deep Dive Series"
LABEL description="Suricata 8.0.3 源码编译与学习环境"

ENV DEBIAN_FRONTEND=noninteractive
ENV SURICATA_VERSION=8.0.3

# 基础构建依赖
RUN apt-get update && apt-get install -y \
    autoconf \
    automake \
    build-essential \
    cargo \
    cbindgen \
    curl \
    git \
    libjansson-dev \
    libpcap-dev \
    libpcre2-dev \
    libtool \
    libyaml-dev \
    make \
    pkg-config \
    rustc \
    zlib1g-dev \
    # 可选但推荐的依赖
    libcap-ng-dev \
    libcap-ng0 \
    libmagic-dev \
    libnet1-dev \
    libnetfilter-queue-dev \
    libnetfilter-queue1 \
    libnfnetlink-dev \
    libnfnetlink0 \
    libnss3-dev \
    libnspr4-dev \
    liblz4-dev \
    libmaxminddb-dev \
    liblua5.1-0-dev \
    python3 \
    python3-pip \
    python3-yaml \
    # 调试与分析工具
    gdb \
    valgrind \
    tcpdump \
    tshark \
    jq \
    vim \
    less \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /opt/suricata

# 复制源码（构建时从仓库根目录 COPY）
COPY . /opt/suricata/

# 编译安装
RUN ./autogen.sh && \
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --enable-lua \
        --enable-geoip \
        --enable-nfqueue \
        --disable-gccmarch-native && \
    make -j$(nproc) && \
    make install && \
    make install-conf && \
    ldconfig

# 安装 suricata-update
RUN pip3 install --no-cache-dir suricata-update && \
    suricata-update

# 创建日志目录
RUN mkdir -p /var/log/suricata /var/run/suricata

# 保留源码用于学习
WORKDIR /opt/suricata

# 默认启动 bash，方便交互式学习
CMD ["/bin/bash"]
