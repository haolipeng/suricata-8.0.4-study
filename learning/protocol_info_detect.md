协议的资产元信息探测功能

| 协议       | 版本信息所在位置                                 | 示例                                                         | 状态 |
| ---------- | ------------------------------------------------ | ------------------------------------------------------------ | ---- |
| MySQL      | Server Greeting 握手包                           |                                                              | 完成 |
| Redis      | 客户端发 INFO server                             | "redis_version:7.2.4"                                        |      |
| Kafka      | ApiVersions Response或 metadata 中的 broker 信息 |                                                              |      |
| FTP        | 首包 220 Banner，连接建立后服务端主动发          | 220 (vsFTPd 3.0.5)，获取成功率取决于/etc/vsftpd.conf中的ftpd_banner=配置，慎重 | 完成 |
| Telnet     | 连接后的 Banner 文本，登录提示前的欢迎信息       | 不好实现                                                     | NO   |
| SSH        | 首包版本交换字符串                               | "SSH-2.0-OpenSSH_9.6p1 Ubuntu..."                            | 完成 |
| HTTP       | Response Server 头                               | "Server: nginx/1.24.0"或"Server: Apache/2.4.58"              | 完成 |
| PostgreSQL | 认证完成后的ParameterStatus 消息                 |                                                              | 完成 |
| X11        |                                                  |                                                              |      |

