# Docker 实验环境

本目录提供 Suricata 8.0.3 源码编译的一键构建环境，用于配合系列文章进行实操学习。

## 快速开始

### 构建镜像

```bash
# 在 docs/docker/ 目录下执行
docker compose build suricata-lab
```

### 启动交互式学习环境

```bash
docker compose run --rm suricata-lab
```

进入容器后，Suricata 已编译安装完成，源码保留在 `/opt/suricata/`。

### 验证安装

```bash
# 在容器内执行
suricata --build-info
suricata -V
```

## 目录说明

```
docker/
├── Dockerfile           # Suricata 构建镜像
├── docker-compose.yml   # 服务编排（含可选 ELK 栈）
├── pcaps/               # 放入你的测试 pcap 文件
└── README.md            # 本文件
```

## 使用 pcap 文件测试

将 pcap 文件放入 `pcaps/` 目录，在容器内即可访问：

```bash
suricata -r /opt/pcaps/your-file.pcap -l /var/log/suricata/
cat /var/log/suricata/eve.json | jq .
```

## ELK 集成（板块二使用）

启动包含 Elasticsearch + Kibana + Logstash 的完整环境：

```bash
docker compose --profile elk up -d
```

- Kibana: http://localhost:5601
- Elasticsearch: http://localhost:9200

## 容器内源码调试

```bash
# 重新编译（修改源码后）
cd /opt/suricata
make -j$(nproc)
make install

# GDB 调试
gdb --args suricata -r /opt/pcaps/test.pcap

# Valgrind 内存检查
valgrind --leak-check=full suricata -r /opt/pcaps/test.pcap
```

## 资源需求

- 磁盘：约 3GB（镜像 + 编译产物）
- 内存：建议 4GB+（如启用 ELK 需 8GB+）
- CPU：编译时间取决于核心数，`make -j$(nproc)` 会自动利用所有核心
