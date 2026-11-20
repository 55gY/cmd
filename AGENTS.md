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
- **主面板**:SS / Mihomo / Reality / Hysteria2 在“已安装”时必须显示端口;端口解析集中在 `common.sh`(`ss_get_port` / `mihomo_get_port` / `reality_get_port` / `hy2_get_port`),口径一致。Hysteria2 为 UDP,监听状态不得复用 TCP 的 `port_listen_str`,须用 `port_listen_udp_str`。
- **面板形式**:主菜单保持扁平结构。**SS / Mihomo / Reality / Hysteria2 / BBR 各有管理子菜单**(`*_menu`),在子菜单顶部显示自己的状态面板;**SSH / System 仍为直接动作**,在执行前先打印一次对应面板。
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
- 命令行(非交互)参数:`install.sh ss config|ss auto|reality config|reality auto|hy2 config|hy2 auto`。
- 改动后务必:逐文件 `bash -n`;能同时 `source lib/common.sh` 与全部 `modules/*.sh` 而无报错、无函数重名。

## 5. SSH 安全(密钥登录 / 端口)—— 防锁死(关键)

- **改动前先体检 sshd 本身**:`enable_key_login` / `change_port` 入口一律先 `ssh_preflight || return 1`。`ssh_health_check` 检查五项(sshd 程序是否存在、**现有配置 `sshd -t` 是否已有存量错误**、unit 是否被 mask、服务/socket 是否在运行、配置端口是否有监听);有异常则展示面板并默认尝试 `ssh_repair`(装 openssh-server、`unmask`、必要时从 `/root/.ssh_cmd_backups` 最近备份恢复、`enable --now` socket/service、`reset-failed`),复检仍失败则需用户明确确认才继续。目的:**避免把"本来就坏"的 sshd 误判成本次改动失败并触发无意义回滚**。修复保守,不擅自改写用户配置。
- **必须区分「运行时问题」与「真正的配置语法错误」**:`sshd -t` 失败并不等于配置写错。以下属运行时问题,改配置文件无用,须自动修复:
  - `Missing privilege separation directory: /run/sshd` → `/run` 是 tmpfs,重启即清空;用 `_ssh_ensure_runtime_dir` 创建(0755 root:root)并写 `/etc/tmpfiles.d/cmd-sshd-runtime.conf` 保证重启后自动重建。
  - `Could not load host key: /etc/ssh/ssh_host_*_key` → 用 `ssh-keygen -A` 生成。
  统一走 `_ssh_config_test`:自动识别上述情况 → 自愈 → 复检,返回 `0=通过 / 1=真配置错误 / 2=运行时问题且修复失败`。**严禁**把运行时问题当配置错误去"从备份恢复配置"(无效,且可能用旧配置覆盖好配置)。`ssh_safe_apply` 校验前先 `_ssh_ensure_runtime_dir`,避免假失败触发无意义回滚。SSH 面板显示「运行时目录」状态。
- 任何 sshd 配置改动**改前必须 `ssh_backup`**(备份 sshd_config + `sshd_config.d` + socket override 到时间戳压缩包)。
- 应用一律走 `ssh_safe_apply`:`sshd -t` 校验 → 重启 → 验证服务 `is-active`;**任一失败自动 `ssh_restore` 回滚**,绝不 `exit` 整个脚本。
- 改端口:默认 [A]追加保留 22;重启前先调 common 的 **`open_firewall <端口> tcp`** 放行本机防火墙(**ufw / firewalld / iptables+ip6tables 双栈**,`-C` 幂等去重,尽力持久化 netfilter-persistent / rules.v4·v6 / `service iptables save`;仅 nftables 无 ufw·firewalld 时提示手动放行);SELinux 用 `semanage port -a || -m`;重启后做两项自检——**新端口在监听**(`ss`)+ **本机 TCP 自连测试**(`_ssh_tcp_check`,优先 `bash /dev/tcp` 回退 `nc`),任一失败即提示回滚;强提示云服务器仍需在安全组另行放行(本机放行/自连不代表外网可达)。
- **禁用密码登录必须是两阶段, 中间夹一次真人实测(2026-11-08 修锁死)**:
  旧流程一次跑完“生成密钥→关密码”, 守卫只是 grep 文件里有没有密钥形状的行,
  从不验证用户手里的私钥是否匹配、sshd 是否真会接受, 结果就是“关完密码和
  密钥都登不上”。新流程: 第一步只开密钥登录(密码保持可用)并核对 `sshd -T`
  生效值; 第二步必须由用户在新会话里真的用密钥登上, 再手输 `yes` 确认
  (`_ssh_confirm_explicit`, 必须手输 yes, 回车不算——这是对 §4“回车=是”约定的
  唯一例外, 因为这道门默认通过等于没设门); 只有确认后才关密码。任何一步失败
  都停在密码还开着的状态。
- **关密码必须同时关 `KbdInteractiveAuthentication`**: 只关
  `PasswordAuthentication` 时, Ubuntu 上密码仍能走键盘交互(默认 yes + UsePAM)
  登录, 等于没关; 三项生效值(PasswordAuthentication=no、
  KbdInteractiveAuthentication=no、PubkeyAuthentication=yes)须在应用后用
  `ssh_effective_value` 逐一核对, 不符即回滚。
- **`set_ssh_config` 契约**: 主文件是唯一事实来源——先清掉全部 drop-in
  (不限文件名, 旧版只认 3 个云文件名会漏网)与主文件全局区的同名行, 再把唯一值
  写进主文件第一个 `Match` 块之前(写进 Match 块之后会落进 Match 上下文, 全局不
  生效); 写完必须用 `ssh_effective_value` 核对生效值, 不要只信文件写了什么。
  清同名行是有意的窄例外: 只删“正要改写的同一个 key”的重复行且只在全局区
  (Match 块内保留), 不是 §6 禁的按关键字类全局删除他人配置。
- **`authorized_keys` 追加必须补尾换行**: 原文件缺尾换行时 `cat >>` 会把新公钥
  吞进上一行注释, 新密钥实际不存在; 追加前先校验每行是合法公钥行
  (`_ssh_validate_authkeys`, 含证书型), 权限每次都修(700 目录 / 600 文件 /
  属主 root / 去 /root 的组写权限 / RHEL 系 `restorecon`), 不只新生成密钥时。
- **回滚定时器先布防再改动**: 关密码那一步须在改配置前 `ssh_arm_autorollback 300`
  (原 120 秒不够下载私钥+开新会话测试), 备份取改动前密码还开着的状态。
- 提供**定时自动回滚** `ssh_arm_autorollback`(默认 120s,`setsid` 脱离会话):另开会话确认可登录后 `touch <keep 文件>` 取消,否则到时自动恢复原配置。sshd 重启不会中断现有会话,故可安全测试。
- **socket 端口必须「IPv4+IPv6 双栈双写」(踩过的坑, 已在 Ubuntu 24.04 实测纠正)**:不能依赖"纯端口 `ListenStream=88` 会自动双栈"——实测部分 systemd 会把纯端口套接字设成 `IPV6_V6ONLY=1`, 结果只监听 `[::]:88`(IPv6), 外部 IPv4 连接直接 `Connection refused`, 且此时 `net.ipv6.bindv6only=0` 也救不了(是 per-socket 覆盖了系统默认)。**可靠写法**是每个端口显式写两条 + 强制 IPv6 单栈, 让 IPv4/IPv6 各绑各的、不抢端口:
  ```
  ListenStream=0.0.0.0:22
  ListenStream=0.0.0.0:88
  ListenStream=[::]:22
  ListenStream=[::]:88
  BindIPv6Only=ipv6-only
  ```
  `configure_ssh_socket_ports` 按此生成; `_ssh_fix_socket_override` 把任何旧写法(纯端口 / 仅 `[::]:` / 重复)规整成上面这种标准双栈写法(幂等); `ssh_health_check` 发现某端口缺少 IPv4 监听(`ss` 无 `0.0.0.0:P`)时自动规整并重启 socket。验证要点: `ss -ltn 'sport = :88'` 应同时出现 `0.0.0.0:88` 和 `[::]:88`, 且 `ssh -4 -p 88 127.0.0.1` 不再 refused。
- **写 socket 端口覆盖时必须去重(踩过的坑)**:`systemctl show -p Listen ssh.socket` 会把同一端口的 IPv4 与 IPv6 各列一条,直接采集会得到重复端口,写出两条 `ListenStream=22` → systemd 重复绑定同一端口 → `Address already in use` → `ssh.socket` failed → `ssh.service` 依赖失败 → **SSH 整体不可用**。`configure_ssh_socket_ports` 写入前必须去重;`_ssh_fix_socket_override` 可修复已损坏的机器(去重重写 + `daemon-reload` + `reset-failed`),并在 `ssh_repair` 早期调用;若仍失败则提议 `systemctl revert ssh.socket` 回到默认端口以先恢复 SSH。
- **socket 激活时 `sshd_config` 的 `Port` 不生效**:端口只由 `ssh.socket` 的 `ListenStream` 决定。面板**不得**拿 `sshd_config` 的 `Port` 当真相——须用 `_ssh_effective_ports` 并逐个标注「监听中/未监听」,socket 模式下另列 `socket 端口(实际生效)` 与 `sshd_config(被忽略)`,并对"只写在 sshd_config、未进 socket"的端口明确告警。`change_port` 在 socket 模式下要提前说明这一点,并在改完后核对 `ListenStream` 是否真的包含新端口。
- **判定 SSH 是否正常时,socket 与 service 任一 `active` 即算正常**(不可二选一,否则 socket 为 static/indirect 而实际跑 service 的机器会被误报);端口用 `_ssh_effective_ports`(`sshd -T` 解析 Include/Match + socket `ListenStream` + 兜底 22),不要只 `grep "^Port "`。
- **修复失败必须输出真实原因**:`ssh_show_diagnostics` 打印两个单元的 enabled/active、`systemctl status` 尾部、`journalctl -u ssh` 与 `-u ssh.socket`、生效端口、`ss -ltnp`。禁止把错误 `>/dev/null 2>&1` 吞掉后只说“仍有问题”。
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

## 7. SOCKS5 (Dante) 模块约束

- 发行版差异: Debian/Ubuntu 为包 `dante-server` + 服务 `danted` + 配置 `/etc/danted.conf`; EL 系为 `sockd` + `/etc/sockd.conf`。用 common 的 `socks5_detect_paths` 统一探测(未安装时给出该发行版默认路径), 端口用 `socks5_get_port` 解析 `internal: ... port = N`。
- **账号/密码/端口全随机**: 端口 `shuf -i 20000-60000`, 账号 `s5_` + 随机十六进制, 密码 20 位随机字母数字。
- Dante 的 `socksmethod: username` 使用**系统账号**认证, 密码无法从 shadow 反查, 因此安装时必须把凭据写入 `${SOCKS5_INFO}`(默认 `/root/.socks5_credentials`, 权限 600)供“查看连接信息”使用。
- 认证账号必须建成**无登录 shell**(`useradd -M -s nologin`), 不得可交互登录。
- `external:` 需要出口网卡名, 用 `ip route get` 推导; 取不到则报错中止, 不要写死 eth0。
- 重置/卸载必须: 先取旧端口与旧账号 → `close_firewall <port> tcp udp` → `userdel` 删除认证账号 → 删除配置/凭据/日志/drop-in。卸载时另行询问是否 purge 软件包。
- 明文 SOCKS5 不加密流量, 查看信息时须提示用户注意, 并提醒云服务器放行安全组。

## 8. Hysteria2 模块约束 (Phase 1: 自签证书, 2026-11-20 新增)

- **基准**:crazypeace/hy2 的极简核心(官方 `get.hy2.sh` + 自签 + 28 行配置)按本项目规范重写;seagullz4/hysteria2 只当二期功能清单,不当基准(见评估: 单体菜单 + Python 双实现 + `/root/hy3` 非标准路径 + 写死 eth0 的端口跳跃 + XanMod 换内核, 均与 §1/§4/§6 冲突)。
- **安装位置(官方脚本决定, 不许自造)**:二进制 `/usr/local/bin/hysteria`、配置 `/etc/hysteria/config.yaml`、服务 `hysteria-server`。不做版本锁定(官方脚本已是最新版时跳过安装);与 Reality 的 `XRAY_VERSION` 锁定不同。
- **默认随机、每次全新节点**:密码 = `cat /proc/sys/kernel/random/uuid`(本地随机, 不许调外部 UUID API、不许由 IP/主机名派生, 与 Reality 的 UUID 同规则);端口默认 **2096**(**UDP**, 与 Reality 的 443/TCP 不同, 别抢 443);自签证书域名默认 `learn.microsoft.com`。
- **自签证书**:EC `prime256v1`、`openssl req -x509`、36500 天。服务以官方安装器创建的 `hysteria` 系统用户运行(非 root), 私钥权限为 **640 + 属组 hysteria**、证书 644、目录 755;取不到服务用户时回退 644 并告警。**绝不许用 crazypeace 的 `chmod 777`**。
- **防火墙**:`open_firewall <端口> udp` / 卸载 `close_firewall <端口> udp`;Hy2 是 UDP, 与 Reality 的 TCP 不同。
- **监听检测**:UDP 套接字无 LISTEN 状态, 详情面板用 `port_listen_udp_str`(common.sh, `ss -lun` 判绑定), 不得用 TCP 的 `port_listen_str`。
- **分享链接**:`hysteria2://<密码>@<IP>:<端口>?alpn=h3&insecure=1&pinSHA256=<指纹>#HY2_<IP>`;指纹 = 证书 DER 的 SHA-256。密码须只含字母/数字/`._~-`, 否则链接会断, 交互输入时校验。
- **配置与 crazypeace 的一处偏差**:它的 `acl.inline` 只有一行被注释掉的规则, 解析后为 null;这里写成显式的 `direct(all)`, 出站保留 `direct` + `socks5(127.0.0.1:1080)` 备选。
- **运行前检测**:已安装且配置有效时先输出有配置 + 分享链接(**不含二维码**), 再用 `confirm` 问是否重装(回车=是, `n` 保留退出);非交互(auto)自动继续。
- **卸载(§6)**:先取端口与证书域名 → 停/禁服务 → 官方脚本 `--remove`(只删二进制与服务单元, **不删配置与 hysteria 用户**, 须手动补) → 删 `/etc/hysteria`、本次的两个证书文件(只删这两个, `/etc/ssl/private` 为共享目录不许整目录删)、`~/_hy2_url_`、服务单元与 `multi-user.target.wants` 软链 → `userdel -r hysteria`(仅当家目录为 `/var/lib/hysteria` 的系统用户) → `close_firewall <端口> udp` → `daemon-reload` / `reset-failed`。`--remove` 不能用 `bash -c "$(curl ...)" --remove`(会被当成 `$0`), 须先下载到临时文件再带参数执行。
- **Phase 1 不做**:ACME 真域名证书、伪装站 `masquerade`、obfs、sniff、端口跳跃。做二期时 ACME 优先, 端口跳跃最后(须先抽象成 common 的防火墙能力, 不许写死 eth0、不许另起 `ipppp.service` 这类私货)。
