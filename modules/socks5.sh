#!/bin/bash
# modules/socks5.sh — SOCKS5 (明文) 管理, 基于 Dante. 依赖 lib/common.sh
# 账号/密码/端口全随机; 认证方式为标准 SOCKS5 用户名密码(username), 不做额外加密。
# 兼容: Debian/Ubuntu(dante-server, danted.conf) 与 EL 系(sockd, sockd.conf)

# 生成随机端口/账号/密码
_socks5_rand_port() { shuf -i 20000-60000 -n 1; }
_socks5_rand_user() { echo "s5_$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 8)"; }
_socks5_rand_pass() { head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20; }

# 出口网卡 (Dante 的 external 需要网卡名或 IP)
_socks5_ext_iface() {
    local i
    i=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(x=1;x<=NF;x++) if($x=="dev"){print $(x+1);exit}}')
    [ -z "$i" ] && i=$(ip -o -4 route show default 2>/dev/null | awk '{print $5}' | head -1)
    [ -z "$i" ] && i=$(ls /sys/class/net 2>/dev/null | grep -E '^(eth|ens|eno|enp|venet|vif)' | head -1)
    echo "$i"
}

# 读取已保存的账号密码 (Dante 用系统账号认证, 密码无法从 shadow 反查, 故安装时留存)
_socks5_load_info() {
    S5_USER=""; S5_PASS=""
    [ -f "$SOCKS5_INFO" ] || return 1
    S5_USER=$(grep -oP '^user=\K.*' "$SOCKS5_INFO" 2>/dev/null | head -1)
    S5_PASS=$(grep -oP '^pass=\K.*' "$SOCKS5_INFO" 2>/dev/null | head -1)
    [ -n "$S5_USER" ]
}

# 状态检测面板 (统一样式)
socks5_status_panel() {
    socks5_detect_paths
    local port; port=$(socks5_get_port)
    panel_top "SOCKS5 (Dante) 状态检测"
    if [ -n "$SOCKS5_BIN" ]; then
        echo -e "程序 (Dante)     : ${GREEN_BOLD}已安装${NC}  ${CYAN}${SOCKS5_BIN}${NC}"
    else
        echo -e "程序 (Dante)     : ${RED_BOLD}未安装${NC}"
    fi
    if [ -f "$SOCKS5_CONF" ]; then
        echo -e "配置文件         : ${GREEN_BOLD}已存在${NC}  ${CYAN}${SOCKS5_CONF}${NC}"
    else
        echo -e "配置文件         : ${RED_BOLD}不存在${NC}"
    fi
    echo -e "服务状态         : $(svc_status_str "${SOCKS5_SERVICE:-danted}")"
    echo -e "监听端口         : ${CYAN}${port:-未知}${NC}  $(port_listen_str "$port")"
    if _socks5_load_info; then
        echo -e "认证账号         : ${CYAN}${S5_USER}${NC}"
    else
        echo -e "认证账号         : ${RED_BOLD}无记录${NC}"
    fi
    panel_bot
}

# 查看配置 (含连接信息)
socks5_view_config() {
    socks5_detect_paths
    if [ ! -f "$SOCKS5_CONF" ] || [ -z "$SOCKS5_BIN" ]; then
        echo -e "${RED}SOCKS5 未安装${NC}"
        return 1
    fi
    local port ip
    port=$(socks5_get_port)
    ip=$(curl -4s -m 5 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -oP 'ip=\K.*')
    # 取不到公网 IP 时回退本机地址 (自包含, 不依赖其它模块)
    if [ -z "$ip" ]; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
        [ -z "$ip" ] && ip=$(ip route get 1 2>/dev/null | awk '/src/{for(x=1;x<=NF;x++) if($x=="src"){print $(x+1);exit}}')
        [ -z "$ip" ] && ip="<服务器IP>"
    fi
    _socks5_load_info

    echo -e "${BLUE}---------- SOCKS5 连接信息 ----------${NC}"
    echo -e "${YELLOW} 地址 (Address)  = ${CYAN}${ip}${NC}"
    echo -e "${YELLOW} 端口 (Port)     = ${CYAN}${port}${NC}"
    echo -e "${YELLOW} 用户名 (User)   = ${CYAN}${S5_USER:-<无记录>}${NC}"
    echo -e "${YELLOW} 密码 (Password) = ${CYAN}${S5_PASS:-<无记录>}${NC}"
    echo -e "${YELLOW} 认证方式        = ${CYAN}username/password (明文 SOCKS5)${NC}"
    echo -e "${BLUE}-------------------------------------${NC}"
    if [ -n "$S5_USER" ] && [ -n "$port" ]; then
        echo -e "${GREEN} 代理地址: ${CYAN}socks5://${S5_USER}:${S5_PASS}@${ip}:${port}${NC}"
        echo -e "${GREEN} 测试命令: ${CYAN}curl -x socks5h://${S5_USER}:${S5_PASS}@${ip}:${port} https://ifconfig.me${NC}"
    fi
    echo -e "${YELLOW} 提示: 明文 SOCKS5 不加密流量, 云服务器请确认安全组已放行该端口。${NC}"
}

# 安装依赖 (Dante)
_socks5_install_deps() {
    echo -e "${BLUE}安装 Dante SOCKS 服务端...${NC}"
    if _exists apt-get; then
        apt-get update -qq >/dev/null 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get install -y dante-server >/dev/null 2>&1
    elif _exists dnf; then
        dnf install -y epel-release >/dev/null 2>&1
        dnf install -y dante-server >/dev/null 2>&1
    elif _exists yum; then
        yum install -y epel-release >/dev/null 2>&1
        yum install -y dante-server >/dev/null 2>&1
    else
        echo -e "${RED}无法识别包管理器, 请手动安装 dante-server${NC}"
        return 1
    fi
    socks5_detect_paths
    if [ -z "$SOCKS5_BIN" ]; then
        echo -e "${RED}Dante 安装失败 (未找到 danted/sockd)${NC}"
        return 1
    fi
    echo -e "${GREEN}✓ Dante 已安装: ${SOCKS5_BIN}${NC}"
}

# 写配置
_socks5_write_config() {
    local port="$1" iface="$2"
    cat > "$SOCKS5_CONF" <<-EOF
# Dante SOCKS5 (明文) —— 由脚本生成
logoutput: /var/log/${SOCKS5_SERVICE}.log
internal: 0.0.0.0 port = ${port}
external: ${iface}

# 认证: 标准 SOCKS5 用户名/密码 (使用系统账号)
socksmethod: username
clientmethod: none
user.privileged: root
user.unprivileged: nobody

client pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error
}

socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    command: connect bind udpassociate
    log: error
    socksmethod: username
}
EOF
}

# 创建/更新认证用的系统账号 (无登录 shell)
_socks5_setup_user() {
    local user="$1" pass="$2" nologin
    nologin=$(command -v nologin 2>/dev/null)
    [ -z "$nologin" ] && { [ -x /usr/sbin/nologin ] && nologin=/usr/sbin/nologin || nologin=/sbin/nologin; }
    if id "$user" >/dev/null 2>&1; then
        usermod -s "$nologin" "$user" >/dev/null 2>&1
    else
        useradd -M -s "$nologin" "$user" >/dev/null 2>&1 || {
            echo -e "${RED}创建账号 ${user} 失败${NC}"; return 1; }
    fi
    echo "${user}:${pass}" | chpasswd >/dev/null 2>&1 || {
        echo -e "${RED}设置账号密码失败${NC}"; return 1; }
    # 记录凭据 (Dante 用系统账号认证, 密码无法回查)
    umask 077
    { echo "user=${user}"; echo "pass=${pass}"; } > "$SOCKS5_INFO"
    chmod 600 "$SOCKS5_INFO" 2>/dev/null
}

# 安装 / 重置 (账号、密码、端口全随机)
socks5_install() {
    check_root
    socks5_detect_paths

    if [ -n "$SOCKS5_BIN" ] && [ -f "$SOCKS5_CONF" ]; then
        echo -e "${YELLOW}检测到 SOCKS5 已安装, 将重置为全新的随机账号/密码/端口。${NC}"
        confirm "是否继续?" || { echo -e "${YELLOW}已取消${NC}"; return 0; }
        # 重置前清理旧账号与旧端口放行
        local old_port old_user
        old_port=$(socks5_get_port)
        _socks5_load_info && old_user="$S5_USER"
        [ -n "$old_port" ] && close_firewall "$old_port" tcp udp
        [ -n "$old_user" ] && userdel "$old_user" >/dev/null 2>&1
    fi

    _socks5_install_deps || return 1

    local port user pass iface
    port=$(_socks5_rand_port)
    user=$(_socks5_rand_user)
    pass=$(_socks5_rand_pass)
    iface=$(_socks5_ext_iface)
    if [ -z "$iface" ]; then
        echo -e "${RED}未能识别出口网卡, 无法配置 Dante${NC}"
        return 1
    fi
    echo -e "${BLUE}出口网卡: ${CYAN}${iface}${NC}"

    _socks5_setup_user "$user" "$pass" || return 1
    _socks5_write_config "$port" "$iface"

    # 放行本机防火墙 (SOCKS5 走 TCP; 开启 udpassociate 故一并放行 UDP)
    open_firewall "$port" tcp udp

    systemctl enable "$SOCKS5_SERVICE" >/dev/null 2>&1
    systemctl restart "$SOCKS5_SERVICE" >/dev/null 2>&1 || service "$SOCKS5_SERVICE" restart >/dev/null 2>&1
    sleep 1

    if systemctl is-active --quiet "$SOCKS5_SERVICE" 2>/dev/null; then
        echo -e "${GREEN}✓ SOCKS5 安装完成并已启动${NC}"
    else
        echo -e "${RED}✗ SOCKS5 服务启动失败, 诊断信息:${NC}"
        systemctl status "$SOCKS5_SERVICE" --no-pager -l 2>/dev/null | tail -12 | sed 's/^/  /'
        journalctl -u "$SOCKS5_SERVICE" --no-pager -n 15 2>/dev/null | tail -15 | sed 's/^/  /'
        return 1
    fi
    echo
    socks5_view_config
}

# 卸载 (清理新增文件/账号/防火墙放行)
socks5_uninstall() {
    check_root
    socks5_detect_paths
    if [ -z "$SOCKS5_BIN" ] && [ ! -f "$SOCKS5_CONF" ]; then
        echo -e "${YELLOW}未检测到 SOCKS5 安装${NC}"
        return 0
    fi
    confirm "${RED}确定要卸载 SOCKS5 (Dante) 并清理其文件?${NC}" || {
        echo -e "${YELLOW}卸载已取消${NC}"; return 0; }

    # 先取端口与账号(配置删除后就读不到了)
    local old_port old_user
    old_port=$(socks5_get_port)
    _socks5_load_info && old_user="$S5_USER"

    systemctl stop "$SOCKS5_SERVICE" >/dev/null 2>&1
    systemctl disable "$SOCKS5_SERVICE" >/dev/null 2>&1

    if confirm "是否同时卸载 dante-server 软件包?"; then
        if _exists apt-get; then
            DEBIAN_FRONTEND=noninteractive apt-get purge -y dante-server >/dev/null 2>&1
        elif _exists dnf; then dnf remove -y dante-server >/dev/null 2>&1
        elif _exists yum; then yum remove -y dante-server >/dev/null 2>&1
        fi
    fi

    # 清理本脚本新增的文件与账号
    rm -f "$SOCKS5_CONF" "$SOCKS5_INFO"
    rm -f "/var/log/${SOCKS5_SERVICE}.log"
    rm -rf "/etc/systemd/system/${SOCKS5_SERVICE}.service.d"
    [ -n "$old_user" ] && userdel "$old_user" >/dev/null 2>&1

    # 回收防火墙放行
    [ -n "$old_port" ] && close_firewall "$old_port" tcp udp

    systemctl daemon-reload >/dev/null 2>&1
    systemctl reset-failed "$SOCKS5_SERVICE" >/dev/null 2>&1
    echo -e "${GREEN}SOCKS5 卸载完成, 相关文件与账号已清理。${NC}"
}

# SOCKS5 管理子菜单 (参照 SS)
socks5_menu() {
    local opt
    while true; do
        clear
        detect_os
        socks5_status_panel
        socks5_detect_paths
        if [ -n "$SOCKS5_BIN" ] && [ -f "$SOCKS5_CONF" ]; then
            socks5_view_config
        fi
        echo "1. 安装/重置 SOCKS5 (随机账号/密码/端口)"
        echo "2. 查看连接信息"
        echo "3. 卸载 SOCKS5"
        echo "0. 返回主菜单"
        read -p "选择操作: " opt
        case $opt in
            1) socks5_install; read -n 1 -p "按任意键继续..." _ ;;
            2) socks5_view_config; read -n 1 -p "按任意键继续..." _ ;;
            3) socks5_uninstall; read -n 1 -p "按任意键继续..." _ ;;
            0) break ;;
            *) echo "无效选项"; sleep 1 ;;
        esac
    done
}
