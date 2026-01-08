# 系统管理脚本
一键式 Linux 服务器配置脚本，集成 SSH 安全配置和 Shadowsocks 代理部署。

## 一键安装
```bash
bash <(curl -Ls https://raw.githubusercontent.com/55gY/cmd/main/install.sh)
```

## 命令行参数

脚本支持非交互式命令行参数：

```bash
# 查看 SS 配置（不含二维码）
./install.sh ss config

# 自动安装/重置 SS（不含二维码）
./install.sh ss auto
```

## 主要功能

### SSH 安全管理
- 一键启用 Root 密钥登录
- 修改/新增 SSH 端口（支持防火墙和 SELinux）
- 修改系统时区

### SS 代理管理
- 一键安装/重置 Shadowsocks
- 自动配置（随机端口、2022-blake3-aes-256-gcm 加密）
- 查看配置信息和二维码
- 一键卸载

## 系统要求
- 支持的系统：Ubuntu, Debian, CentOS, RHEL, Fedora, Rocky Linux, AlmaLinux
- 支持的架构：x86_64, aarch64, armv7, armv6, i686
- 需要 root 权限
