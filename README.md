# 系统管理脚本
自用快捷脚本

## 一键安装
```bash
bash <(curl -Ls https://raw.githubusercontent.com/55gY/cmd/main/cmd.sh)
```

## 命令行参数

脚本支持非交互式命令行参数：

```bash
# 查看 SS 配置（不含二维码）
./cmd.sh ss config

# 自动安装/重置 SS（不含二维码，非交互模式）
./cmd.sh ss auto
```

## 主要功能

### 1. SSH 安全管理
- 一键启用 Root 密钥登录（4096 位 RSA，自动清理云平台限制）
- 修改/新增 SSH 端口（自动配置防火墙和 SELinux）

### 2. SS 代理管理
- 一键安装/重置 Shadowsocks（最新版本，多架构支持）
- 自动配置（随机端口，2022-blake3-aes-256-gcm 加密）
- 查看配置和二维码
- 一键卸载

### 3. BBR 网络加速
- 启用 TCP BBR 拥塞控制（内核 4.9+ 或自动升级）
- 系统网络优化（TCP 参数、文件描述符、SSH 保活）
- 虚拟化环境兼容性检测

### 4. 系统配置
- 修改系统时区（Asia/Shanghai）
- 一键安装中文字体（WQY）和 Locale（zh_CN.UTF-8）

### 5. 系统状态面板
- 实时显示系统信息（OS、架构、时区、Locale、SSH 状态、SS 状态、BBR 状态等）

## 系统要求
- **支持的系统**：Ubuntu, Debian, CentOS, RHEL, Fedora, Rocky Linux, AlmaLinux
- **支持的架构**：x86_64, aarch64, armv7, armv6, i686
- **需要 root 权限**
- **BBR 功能**：需要内核 4.9+ 或支持内核升级的系统

## 安全特性
- ✅ 自动检测云平台配置文件并处理
- ✅ 配置修改前自动备份
- ✅ SSH 配置语法检测
- ✅ 强密码自动生成（SS）
- ✅ 现代化加密算法（2022-blake3-aes-256-gcm）
- ✅ 防火墙自动配置
- ✅ SELinux 策略自动处理

## 使用建议
1. **首次使用**：建议先查看系统状态面板，了解当前配置
2. **SSH 密钥登录**：配置后务必测试密钥登录成功再断开当前会话
3. **BBR 加速**：内核升级有风险，建议在测试环境先验证
4. **中文环境**：配置后需完全退出并重新登录才能显示中文欢迎信息
5. **端口修改**：建议保留 22 端口以防配置错误导致无法登录

## 兼容性说明
- 自动识别并兼容 Debian/Ubuntu 系统的 SSH 服务名（ssh）
- 自动识别并兼容 CentOS/RHEL 系统的 SSH 服务名（sshd）
- 支持云平台特殊配置（AWS、Google Cloud 等）
- 虚拟化环境检测（不支持 LXC/OpenVZ 内核升级）
