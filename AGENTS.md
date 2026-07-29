# AGENTS / 项目关键约束

本文件记录本仓库(系统管理脚本)的**关键约束与设计规则**,后续任何人或 AI 改动前请先阅读并遵守。
(采用通用约定名 `AGENTS.md`,多数 AI 编码工具会自动识别本文件。)

---

## 1. 目录结构与加载机制(不可破坏)

```
install.sh        入口:加载器 + 系统状态面板 + 主菜单 + 命令行分发
lib/common.sh     共用依赖 + 全部功能的“状态检测”
modules/*.sh      各功能实现,按需加载(.sh 后缀)
```

- **状态检测必须放在 `lib/common.sh`**(随 `install.sh` 一起加载)。目的:运行脚本即可显示**全部**功能状态,**无需下载任何模块**。严禁把状态检测写进 `modules/`。
- **`modules/*.sh` 按需加载**:仅当用户在菜单中选中该功能时才加载(本地存在则用本地;`curl` 一键模式则从仓库 raw 地址下载到**本次会话临时目录**,退出清理)。**禁止**一次性预下载全部模块。
- **模块之间不得互相调用函数**:每个模块只能依赖“自身 + `common.sh`”。跨模块引用会在按需加载时报未定义。(可用静态检查验证:模块内不得出现其它模块定义的函数名。)
- 仓库地址通过环境变量 `CMD_REPO_BASE` 可覆盖(默认 `https://raw.githubusercontent.com/55gY/cmd/main`)。
- 两种运行方式都必须可用:`bash <(curl -Ls .../install.sh)` 与 `git clone` 后 `./install.sh`。

### 新增一个功能模块的标准动作
1. `modules/<name>.sh`:实现功能 + `<name>_status_panel`(统一样式)+(如有子菜单)`<name>_menu`。
2. `lib/common.sh`:加入该功能的**状态检测**(供主面板)与**端口/关键值解析器**(集中,主面板与详情面板共用)。需要开放端口时**复用 common 的 `open_firewall <端口> [协议...]`**(协议默认 tcp,可传 `tcp udp`),不要在模块内自己写防火墙逻辑。
3. `install.sh`:主菜单加一项;分发处 `load_module <name>` 后调用其入口。
4. 全部文件 `bash -n` 通过;确认无跨模块函数引用、无函数重名。

---

## 2. 状态面板规范(统一样式)

- 一律用 `common.sh` 的 `panel_top "标题"` / `panel_bot` 包裹;行内状态用 `svc_status_str <服务>`、`port_listen_str <端口>`。
- **配色语义**:🟢 绿=正常/运行中/更安全;🟡 黄=已安装未运行;🔴 红=未安装/未启用/不安全。
- **主面板**:SS / Mihomo / Reality 在“已安装”时必须显示端口;端口解析集中在 `common.sh`(`ss_get_port` / `mihomo_get_port` / `reality_get_port`),口径一致。
- **面板形式**:主菜单保持扁平结构。**SS / Mihomo / Reality / BBR 各有管理子菜单**(`*_menu`),在子菜单顶部显示自己的状态面板;**SSH / System 仍为直接动作**,在执行前先打印一次对应面板。
- 主菜单第 2 项为「BBR 网络优化管理」→ `bbr_menu`(内含 启用/应用优化、还原本脚本写入的配置)。还原入口只放在该子菜单内,不占主菜单项。

---

## 3. Reality(VLESS + Xray)模块约束

- **默认随机、每次全新节点**:
  - UUID = `cat /proc/sys/kernel/random/uuid`(不再用外部 UUID API,不再由 IP/主机名派生)。
  - x25519 密钥 = `xray x25519`(**无种子**);解析用**不加引号**的 `echo ${tmp_key} | awk '{print $2}'`(私钥)/`$4`(公钥)。v25.10.15 输出为 `PrivateKey:` / `Password:`(即公钥)/ `Hash32:` 三行。
  - ShortID = `head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n'`(16 位十六进制、偶数长度)。
- **config.json 必须保留 `// ***` 标记**:入站端口解析依赖它(失败时回退到“去注释后取第一个 port”)。
- 分享链接需要**公钥**,而 config 只存**私钥** → 用 `xray x25519 -i <私钥>` 反推公钥。
- **运行前检测**:已安装则输出现有配置 + `vless://` 分享链接(**不含二维码**),再询问是否重装(按统一约定:**回车=是**重装,输入 `n` 保留现有并退出);非交互(带参数/环境变量)自动继续。独立脚本另提供 `bash install.sh uninstall` 卸载并清理全部新增文件。
- **Reality 不得启用 TCP Fast Open**(`fast-open=false`)。
- `tls-verification` / `udp-relay` / `fast-open` 是 **Quantumult X 客户端**参数,**不属于**标准 `vless://` 分享链接,也**不写入服务端 config**;Clash 用 `udp` / `skip-cert-verify` / `tfo`。Reality 服务端没有“证书验证”字段。这三个开关**不做进脚本**。

---

## 4. 通用与兼容

- **确认提示统一用 common 的 `confirm "问题"`**:约定 **直接回车 = 确认(是)**,输入 `n` / `no` 才拒绝(其它输入按"是"处理)。禁止再手写 `(y/n)` / `[y/N]` 之类的判断,以保证全项目交互一致。用法:`if confirm "…"; then …; fi` 或 `confirm "…" || return`。
- **需 root**;支持多发行版(apt / yum,`install_package_if_missing`)与多架构。
- **去除**任何联系方式/群链接/教程视频链接/冗余说明。
- 每个脚本以 `#!/bin/bash` 开头。
- 命令行(非交互)参数:`install.sh ss config|ss auto|reality config|reality auto`。
- 改动后务必:逐文件 `bash -n`;能同时 `source lib/common.sh` 与全部 `modules/*.sh` 而无报错、无函数重名。

## 5. SSH 安全(密钥登录 / 端口)—— 防锁死(关键)

- **改动前先体检 sshd 本身**:`enable_key_login` / `change_port` 入口一律先 `ssh_preflight || return 1`。`ssh_health_check` 检查五项(sshd 程序是否存在、**现有配置 `sshd -t` 是否已有存量错误**、unit 是否被 mask、服务/socket 是否在运行、配置端口是否有监听);有异常则展示面板并默认尝试 `ssh_repair`(装 openssh-server、`unmask`、必要时从 `/root/.ssh_cmd_backups` 最近备份恢复、`enable --now` socket/service、`reset-failed`),复检仍失败则需用户明确确认才继续。目的:**避免把"本来就坏"的 sshd 误判成本次改动失败并触发无意义回滚**。修复保守,不擅自改写用户配置。
- 任何 sshd 配置改动**改前必须 `ssh_backup`**(备份 sshd_config + `sshd_config.d` + socket override 到时间戳压缩包)。
- 应用一律走 `ssh_safe_apply`:`sshd -t` 校验 → 重启 → 验证服务 `is-active`;**任一失败自动 `ssh_restore` 回滚**,绝不 `exit` 整个脚本。
- 改端口:默认 [A]追加保留 22;重启前先调 common 的 **`open_firewall <端口> tcp`** 放行本机防火墙(**ufw / firewalld / iptables+ip6tables 双栈**,`-C` 幂等去重,尽力持久化 netfilter-persistent / rules.v4·v6 / `service iptables save`;仅 nftables 无 ufw·firewalld 时提示手动放行);SELinux 用 `semanage port -a || -m`;重启后做两项自检——**新端口在监听**(`ss`)+ **本机 TCP 自连测试**(`_ssh_tcp_check`,优先 `bash /dev/tcp` 回退 `nc`),任一失败即提示回滚;强提示云服务器仍需在安全组另行放行(本机放行/自连不代表外网可达)。
- **禁用密码登录前必须确认 `authorized_keys` 含有效公钥**,否则拒绝禁用。
- 提供**定时自动回滚** `ssh_arm_autorollback`(默认 120s,`setsid` 脱离会话):另开会话确认可登录后 `touch <keep 文件>` 取消,否则到时自动恢复原配置。sshd 重启不会中断现有会话,故可安全测试。
- **兼容 systemd socket 激活(Ubuntu 22.10+/24.04 的 `ssh.socket`)**:此时端口由 socket 的 `ListenStream` 控制,**只改 `sshd_config` 并重启 `ssh` 服务无效**。`configure_ssh_socket_ports` 写 socket 的 `ListenStream` override;`ssh_safe_apply` 经 `ssh_is_socket_activated` 判定后重启 **`ssh.socket`**(而非 `ssh.service`),并以 socket 是否 `active` 作为存活判据——socket 模式下 `ssh.service` 常态 `inactive` 属正常,**不得据此误判失败而回滚**。状态面板显示“激活方式: systemd socket / 传统 service”。

## 6. 卸载与还原(必须彻底)

- **卸载动作必须清理本项目新增的全部文件**,并**安全还原被修改过的系统文件**:
  - 新增文件(本项目独占)→ 直接删除:二进制、配置目录、日志目录、systemd unit 与 `*.service.d` drop-in、节点信息文件(如 `~/_vless_reality_url_`)、下载的辅助脚本、`/etc/sysctl.d/99-bbr.conf` 之类专属 drop-in。
  - **系统内置/共享配置文件(如 `/etc/sysctl.conf`、`/etc/security/limits.conf`、`sshd_config`)严禁整文件覆盖还原** —— 其它程序可能也修改过同一文件,整文件回滚会破坏环境。必须**只清理本功能写入的数据**:
    - 写入时一律用 `config_block_write <tag> <文件> <内容>`,内容包在 `# >>> cmd:<tag> >>> … # <<< cmd:<tag> <<<` 标记块内(**幂等**,重复执行不叠加)。
    - 还原时用 `config_block_remove <tag> <文件>`,只删该标记块。
    - 旧版本无标记的残留,用 `config_line_remove <文件> <整行...>` **仅删除与本项目写入值完全一致的行**(`grep -vxF`,不会误伤 `fq_codel`、`bbr2`、被注释的同名行)。
    - **禁止**用 `sed -i '/关键字/d'` 全局删除某类配置行 —— 那会删掉别人写的同类配置。需要覆盖生效时,把本项目块追加在文件末尾(sysctl 后者生效)即可,不要删他人的行。
  - `backup_file` / `restore_file` 仅限**本项目独占文件**,或**同一次操作内的即时回滚**(如 SSH 改配置失败时秒级回退,窗口极短);不得用于共享系统文件的长期还原。
- **必须回收安装时放行的防火墙端口**:调用 common 的 `close_firewall <端口> [协议...]`(`open_firewall` 的逆操作,iptables 分支会循环删除重复规则并持久化)。
- **顺序要求**:先从配置解析出端口(`*_get_port`),**再**删除配置文件——否则端口丢失就无法回收放行。
- 停服顺序:`stop` → `disable` → 删文件 → `daemon-reload` → `reset-failed`。
- 卸载前一律用 `confirm` 二次确认;不代为卸载第三方组件(如 WARP)时需明确提示用户。
