#!/bin/bash
# modules/ss.sh — Shadowsocks 管理. 依赖 lib/common.sh

get_latest_version() {
    echo -e "${BLUE}正在获取 SS 最新版本...${NC}"
    SS_VERSION=$(wget -qO- https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases 2>/dev/null | \
                 jq -r '[.[] | select(.prerelease == false) | select(.draft == false) | .tag_name] | .[0]' 2>/dev/null)
    
    if [[ -z ${SS_VERSION} ]]; then
        echo -e "${RED}获取 SS 最新版本失败！${NC}"
        return 1
    fi
    
    SS_VERSION=${SS_VERSION#v}
    echo -e "${GREEN}检测到 SS 最新版本为 [ ${SS_VERSION} ]${NC}"
}

# 下载 SS
download_ss() {
    local version=$1
    local arch=$2
    local url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${version}"
    local filename="shadowsocks-v${version}.${arch}.tar.xz"
    
    echo -e "${BLUE}开始下载 SS ${version}...${NC}"
    
    cd /tmp
    wget --no-check-certificate -N "${url}/${filename}" 2>/dev/null
    
    if [[ ! -e "${filename}" ]]; then
        echo -e "${RED}SS 下载失败！${NC}"
        return 1
    fi
    
    if ! tar -xf "${filename}" 2>/dev/null; then
        echo -e "${RED}SS 解压失败！${NC}"
        rm -f "${filename}"
        return 1
    fi
    
    if [[ ! -e "ssserver" ]]; then
        echo -e "${RED}SS 解压后未找到主程序！${NC}"
        return 1
    fi
    
    mkdir -p "${INSTALL_DIR}"
    chmod +x ssserver
    mv -f ssserver "${BINARY_PATH}"
    rm -f sslocal ssmanager ssservice ssurl "${filename}"
    
    echo -e "${GREEN}SS ${version} 下载安装完成！${NC}"
}

# 安装系统服务
install_ss_service() {
    echo -e "${BLUE}开始安装 SS 系统服务...${NC}"
    cat > /etc/systemd/system/ss.service << EOF
[Unit]
Description=SS Service
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
Type=simple
User=root
ExecStart=${BINARY_PATH} -c ${CONFIG_PATH}
ExecStop=/usr/bin/killall -9 ssserver
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3s
KillMode=process
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ss >/dev/null 2>&1
    echo -e "${GREEN}SS 服务配置完成！${NC}"
}

# 安装依赖
install_ss_dependencies() {
    echo -e "${BLUE}开始安装 SS 系统依赖...${NC}"
    
    if [[ "$OS_ID" == "centos" || "$OS_ID" == "rhel" ]]; then
        yum update -y >/dev/null 2>&1
        yum install -y jq gzip wget curl unzip xz openssl qrencode tar >/dev/null 2>&1
    else
        apt-get update >/dev/null 2>&1
        apt-get install -y jq gzip wget curl unzip xz-utils openssl qrencode tar >/dev/null 2>&1
    fi
    
    echo -e "${GREEN}系统依赖安装完成！${NC}"
}

# 自动配置 SS
auto_config_ss() {
    echo -e "${BLUE}开始自动配置 SS...${NC}"
    
    SS_PORT=$(shuf -i 10000-65535 -n 1)
    SS_METHOD="2022-blake3-aes-256-gcm"
    SS_PASSWORD=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 | head -c 44)
    SS_TFO=false
    SS_DNS="8.8.8.8,114.114.115.115"
    
    echo -e "${GREEN}自动配置完成！${NC}"
    echo -e "端口：${YELLOW}${SS_PORT}${NC}"
    echo -e "密码：${YELLOW}${SS_PASSWORD}${NC}"
    echo -e "加密：${YELLOW}${SS_METHOD}${NC}"
    
    # 配置防火墙 (复用 common 的通用放行: tcp+udp, v4+v6, 尽力持久化)
    open_firewall "$SS_PORT" tcp udp
}

# 写入配置文件
write_ss_config() {
    cat > ${CONFIG_PATH} << EOF
{
    "server": "::",
    "server_port": ${SS_PORT},
    "password": "${SS_PASSWORD}",
    "method": "${SS_METHOD}",
    "fast_open": ${SS_TFO},
    "mode": "tcp_and_udp",
    "nameserver": "${SS_DNS}",
    "user": "nobody",
    "timeout": 300
}
EOF
    echo -e "${GREEN}配置文件写入完成！${NC}"
}

# 查看 SS 配置
view_ss_config() {
    local show_qr="${1:-true}"  # 默认显示二维码
    
    if [[ ! -f "${CONFIG_PATH}" ]]; then
        echo -e "${RED}SS 未安装${NC}"
        return 1
    fi
    
    # 获取IP
    local ipv4=$(curl -m 2 -s4 https://api.ipify.org 2>/dev/null)
    [[ -z "${ipv4}" ]] && ipv4="获取失败"
    
    # 读取配置
    local port=$(jq -r '.server_port' "${CONFIG_PATH}" 2>/dev/null)
    local password=$(jq -r '.password' "${CONFIG_PATH}" 2>/dev/null)
    local method=$(jq -r '.method' "${CONFIG_PATH}" 2>/dev/null)
    local tfo=$(jq -r '.fast_open' "${CONFIG_PATH}" 2>/dev/null)
    local dns=$(jq -r '.nameserver // empty' "${CONFIG_PATH}" 2>/dev/null)

    echo -e "\n${BLUE}=============== SS 配置信息 ===============${NC}"
    echo -e "地址: ${GREEN}${ipv4}${NC}"
    echo -e "端口: ${GREEN}${port}${NC}"
    echo -e "密码: ${GREEN}${password}${NC}"
    echo -e "加密: ${GREEN}${method}${NC}"
    echo -e "TFO : ${GREEN}${tfo}${NC}"
    [[ ! -z "${dns}" ]] && echo -e "DNS : ${GREEN}${dns}${NC}"
    echo -e "${BLUE}===========================================${NC}"

    # 生成 SS 链接
    if [[ "${ipv4}" != "获取失败" ]]; then
        local userinfo=$(echo -n "${method}:${password}" | base64 -w 0)
        local ss_url="ss://${userinfo}@${ipv4}:${port}#SS-${ipv4}"
        echo -e "\n${YELLOW}SS 链接:${NC}"
        echo -e "${GREEN}${ss_url}${NC}"
        
        # 根据参数决定是否显示二维码
        if [[ "$show_qr" == "true" ]] && command -v qrencode &> /dev/null; then
            echo -e "\n${YELLOW}二维码:${NC}"
            echo "${ss_url}" | qrencode -t UTF8
        fi
    fi
    echo ""
}

# 一键安装 SS
install_ss() {
    local show_qr="${1:-true}"  # 默认显示二维码
    local auto_confirm="${2:-false}"  # 是否自动确认（非交互模式）
    
    echo -e "\n${BLUE}===========================================${NC}"
    echo -e "${BLUE}        一键安装 Shadowsocks (SS)         ${NC}"
    echo -e "${BLUE}===========================================${NC}\n"
    
    if [[ "$OS_ARCH" == "unknown" ]]; then
        echo -e "${RED}不支持的系统架构${NC}"
        return 1
    fi
    
    if [[ -e ${BINARY_PATH} ]]; then
        echo -e "${YELLOW}检测到 SS 已安装，将重置配置...${NC}"
        if [[ "$auto_confirm" != "true" ]]; then
            read -p "是否继续？(y/n): " confirm
            [[ ! "$confirm" =~ ^[Yy]$ ]] && return
        else
            echo -e "${GREEN}[自动模式] 自动确认重置配置${NC}"
        fi
    fi
    
    # 自动配置
    auto_config_ss
    
    # 如果未安装，执行完整安装流程
    if [[ ! -e ${BINARY_PATH} ]]; then
        install_ss_dependencies
        get_latest_version || return 1
        download_ss "${SS_VERSION}" "${OS_ARCH}" || return 1
        install_ss_service
    fi
    
    # 写入配置
    write_ss_config
    
    # 启动服务
    echo -e "${BLUE}正在启动 SS 服务...${NC}"
    systemctl restart ss 2>/dev/null || systemctl start ss
    
    sleep 2
    
    if systemctl is-active ss >/dev/null 2>&1; then
        echo -e "${GREEN}SS 安装/重置并启动成功！${NC}\n"
        view_ss_config "$show_qr"
    else
        echo -e "${RED}SS 启动失败，请检查日志！${NC}"
        echo -e "查看日志: systemctl status ss"
    fi
}

# 卸载 SS
uninstall_ss() {
    if [[ ! -e ${BINARY_PATH} ]]; then
        echo -e "${RED}SS 未安装${NC}"
        return
    fi
    
    echo -e "\n${RED}确定要卸载 SS ? (y/N)${NC}"
    read -e -p "请确认: " unyn
    [[ ! "$unyn" =~ ^[Yy]$ ]] && echo -e "${YELLOW}卸载已取消${NC}" && return
    
    echo -e "${BLUE}正在卸载 SS...${NC}"
    systemctl stop ss 2>/dev/null
    systemctl disable ss 2>/dev/null
    rm -f /etc/systemd/system/ss.service
    systemctl daemon-reload
    rm -rf "${INSTALL_DIR}"
    echo -e "${GREEN}SS 卸载完成！${NC}"
}

# SS 状态检测面板 (统一样式)
ss_status_panel() {
    local port; port=$(ss_get_port)
    panel_top "SS 状态检测"
    if [[ -f "$BINARY_PATH" ]]; then
        echo -e "程序 (Binary)    : ${GREEN_BOLD}已安装${NC}"
    else
        echo -e "程序 (Binary)    : ${RED_BOLD}未安装${NC}"
    fi
    if [[ -f "$CONFIG_PATH" ]]; then
        echo -e "配置文件         : ${GREEN_BOLD}已存在${NC}"
    else
        echo -e "配置文件         : ${RED_BOLD}不存在${NC}"
    fi
    echo -e "服务状态         : $(svc_status_str ss)"
    echo -e "监听端口         : ${CYAN}${port:-未知}${NC}  $(port_listen_str "$port")"
    panel_bot
}

ss_menu() {
    while true; do
        clear
        detect_os
        ss_status_panel
        # 已安装则附带显示分享配置(不含二维码)
        if [[ -f "$BINARY_PATH" && -f "$CONFIG_PATH" ]]; then
            view_ss_config false
        fi
        echo "1. 安装/重置 SS"
        echo "2. 查看完整配置（含二维码）"
        echo "3. 卸载 SS"
        echo "0. 返回主菜单"
        read -p "选择操作: " opt
        case $opt in
            1) install_ss true false; read -n 1 -p "按任意键继续..." ;;
            2) view_ss_config true; read -n 1 -p "按任意键继续..." ;;
            3) uninstall_ss; read -n 1 -p "按任意键继续..." ;;
            0) break ;;
            *) echo "无效选项"; sleep 1 ;;
        esac
    done
}
