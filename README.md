# 系统管理脚本 (模块化版)

自用快捷脚本。已由单文件 `cmd.sh` 重构为**模块化目录**:入口 `install.sh` 只负责加载依赖、显示状态面板与菜单;各功能实现拆分到 `modules/` 并**按需加载**。

> 参与改动前请先阅读 [AGENTS.md](AGENTS.md):其中记录了目录结构、按需加载、统一状态面板与 Reality 等**关键约束**(多数 AI 工具会自动识别该文件)。

## 一键安装

```bash
bash <(curl -Ls https://raw.githubusercontent.com/55gY/cmd/main/install.sh)
```

也可 `git clone` 后本地运行 `./install.sh`（此时按相对路径加载,不需要联网下载模块）。

## 目录结构

```
install.sh          # 入口:加载器 + 系统状态面板 + 主菜单 + 命令行分发
lib/
  common.sh         # 共用依赖:颜色/全局变量、check_root、detect_os、
                    #           全部功能的“状态检测”、通用依赖安装器
modules/            # 功能模块,按需下载(仅在菜单中选中该功能时才加载)
  ssh.sh            # SSH 密钥登录 / 端口
  ss.sh             # Shadowsocks
  bbr.sh            # BBR + 系统优化
  system.sh         # 时区 / 中文字体 + Locale
  mihomo.sh         # Mihomo
  reality.sh        # VLESS + Reality (Xray)
  socks5.sh         # SOCKS5 (明文, Dante)
```

- **状态检测集中在 `lib/common.sh`**,随 `install.sh` 一起加载,因此一进入主菜单即可显示**全部**功能状态,无需下载任何模块。
- **功能模块按需加载**:只有在菜单中选择某项功能时,才从本地(或仓库 raw 地址)加载对应 `modules/*.sh`,不会一次性拉取全部。远程模式下载到本次会话的临时目录,退出自动清理。
- 仓库地址可用环境变量覆盖:`CMD_REPO_BASE=https://your.mirror/path`。

## 命令行参数（非交互）

```bash
# 查看 SS 配置（不含二维码）
./install.sh ss config
# 自动安装/重置 SS（不含二维码,非交互）
./install.sh ss auto

# 查看 Reality 配置（含分享链接,不含二维码）
./install.sh reality config
# 自动安装/重置 Reality（随机全新节点,非交互）
./install.sh reality auto
```

## 主要功能

1. **SSH 安全管理** — 一键 Root 密钥登录(4096 位 RSA)、修改/新增 SSH 端口(联动防火墙/SELinux/ssh.socket)。
2. **SS 代理管理** — 一键安装/重置 Shadowsocks(2022-blake3-aes-256-gcm、随机端口)、查看配置/二维码、卸载。
3. **BBR 网络加速** — 启用 BBR、系统网络优化、虚拟化兼容检测。
4. **Mihomo 代理管理** — 一键安装/重置、默认配置(订阅/Mixed/TUN)、延迟测试、卸载。
5. **系统配置** — 时区 Asia/Shanghai、中文字体(WQY)+Locale。
6. **Reality (VLESS) 管理** — 一键安装/重装 Xray VLESS+Reality;**UUID/x25519 密钥/ShortID 默认随机**;运行前分项检测面板(程序/配置/服务/端口监听);查看配置 + 分享链接 + 二维码;卸载。
7. **SOCKS5 (明文) 管理** — 基于 Dante 一键安装/重置;**账号、密码、端口全随机**;标准 SOCKS5 用户名密码认证(不加密);查看连接信息;卸载(清理配置/账号/日志/防火墙放行)。
8. **系统状态面板** — 实时显示 OS/架构/时区/Locale/SSH/SS/Mihomo/**Reality**/**SOCKS5**/BBR 等状态。

## 系统要求
- 系统:Ubuntu, Debian, CentOS, RHEL, Fedora, Rocky, AlmaLinux
- 架构:x86_64, aarch64, armv7, armv6, i686
- 需要 root 权限
