#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

SSH_CONF="/etc/ssh/sshd_config"
AUTH_KEYS="/root/.ssh/authorized_keys"

# SS 相关配置
INSTALL_DIR="$HOME/ss"
BINARY_PATH="$HOME/ss/ssserver"
CONFIG_PATH="$HOME/ss/config.json"
SS_VERSION=""
SS_PORT=""
SS_PASSWORD=""
SS_METHOD=""
SS_TFO=""
SS_DNS=""
OS_ARCH=""

# --- 检查 root 权限 ---
check_root() {
    if [[ $EUID != 0 ]]; then
        echo -e "${RED}当前非ROOT账号，无法继续操作，请使用 sudo su 命令获取ROOT权限${NC}"
        exit 1
    fi
}

# --- 1. 系统特征检测 ---
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=$NAME
        OS_ID=$ID # ubuntu, centos, debian, rhel 等
    else
        OS_NAME="Unknown"
        OS_ID="unknown"
    fi

    # 识别 SSH 服务名
    if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
        SERVICE_NAME="ssh"
    else
        SERVICE_NAME="sshd"
    fi

    # 检测是否安装了 SELinux (通常在 CentOS/RHEL 系)
    SELINUX_STATE="未安装/禁用"
    if command -v getenforce >/dev/null; then
        SELINUX_STATE=$(getenforce)
    fi

    # 检测当前时区
    CURRENT_TIMEZONE="未知"
    if command -v timedatectl >/dev/null 2>&1; then
        CURRENT_TIMEZONE=$(timedatectl show -p Timezone --value 2>/dev/null)
    fi
    # 如果 timedatectl 失败，尝试从 /etc/localtime 读取
    if [[ -z "$CURRENT_TIMEZONE" || "$CURRENT_TIMEZONE" == "未知" ]]; then
        if [ -L /etc/localtime ]; then
            local tz_path=$(readlink -f /etc/localtime)
            CURRENT_TIMEZONE=$(echo "$tz_path" | sed 's|.*/zoneinfo/||')
        fi
    fi
    [ -z "$CURRENT_TIMEZONE" ] && CURRENT_TIMEZONE="未知"
    
    # 检测系统架构
    local arch=$(uname -m)
    case "${arch}" in
        "x86_64") OS_ARCH="x86_64-unknown-linux-gnu" ;;
        "aarch64") OS_ARCH="aarch64-unknown-linux-gnu" ;;
        "armv7l"|"armv7") OS_ARCH="armv7-unknown-linux-gnueabihf" ;;
        "armv6l") OS_ARCH="arm-unknown-linux-gnueabi" ;;
        "i686"|"i386") OS_ARCH="i686-unknown-linux-musl" ;;
        *) OS_ARCH="unknown" ;;
    esac
}

# --- 2. 状态面板 ---
check_status() {
    clear
    detect_os
    echo -e "${BLUE}================ 系统与 SSH 环境状态 ================${NC}"
    echo -e "操作系统     : ${YELLOW}$OS_NAME${NC}"
    echo -e "系统架构     : ${YELLOW}$OS_ARCH${NC}"
    echo -e "SELinux 状态 : ${YELLOW}$SELINUX_STATE${NC}"
    echo -e "系统时区     : ${YELLOW}$CURRENT_TIMEZONE${NC}"
    echo -e "当前 Locale   : ${YELLOW}$(locale 2>/dev/null | grep "^LANG=" | cut -d= -f2 || echo "未知")${NC}"
    
    # 检测 Root 登录状态
    local root_login=$(grep "^PermitRootLogin" $SSH_CONF | awk '{print $2}')
    [ -z "$root_login" ] && root_login="默认(prohibit-password)"
    
    # 检测密码验证状态
    local pwd_auth=$(grep "^PasswordAuthentication" $SSH_CONF | awk '{print $2}')
    [ -z "$pwd_auth" ] && pwd_auth="yes(默认)"
    
    # 检测端口
    local ports=$(grep "^Port " $SSH_CONF | awk '{print $2}' | xargs)
    [ -z "$ports" ] && ports="22(默认)"
    
    # 检测密钥文件
    local auth_file_status="${RED}不存在${NC}"
    [ -f "$AUTH_KEYS" ] && auth_file_status="${GREEN}已存在${NC} ($(ls -lh $AUTH_KEYS | awk '{print $5}'))"

    # 检测 SS 安装状态
    local ss_status="${RED}未安装${NC}"
    if [[ -f "$BINARY_PATH" && -f "$CONFIG_PATH" ]]; then
        if systemctl is-active ss >/dev/null 2>&1; then
            ss_status="${GREEN}已安装 + 运行中${NC}"
        else
            ss_status="${YELLOW}已安装 未运行${NC}"
        fi
    fi

    echo -e "Root 登录     : ${YELLOW}$root_login${NC}"
    echo -e "密码验证     : ${YELLOW}$pwd_auth${NC}"
    echo -e "SSH 端口      : ${GREEN}[ $ports ]${NC}"
    echo -e "密钥文件状态 : $auth_file_status"
    echo -e "SS 状态       : $ss_status"
    echo -e "${BLUE}=====================================================${NC}"
}

# --- 3. 重启 SSH 服务 (兼容多系统) ---
restart_service() {
    echo -e "${BLUE}正在校验配置并重启 $SERVICE_NAME 服务...${NC}"
    sshd -t
    if [ $? -eq 0 ]; then
        systemctl restart $SERVICE_NAME
        echo -e "${GREEN}服务已重启生效。${NC}"
    else
        echo -e "${RED}配置文件语法检测失败，请手动检查 $SSH_CONF${NC}"
        exit 1
    fi
}

# --- 4. 功能：启用密钥登录 ---
enable_key_login() {
    echo -e "\n${YELLOW}[操作] 正在配置 Root 密钥登录...${NC}"
    mkdir -p /root/.ssh && chmod 700 /root/.ssh

    if [ ! -f "$AUTH_KEYS" ]; then
        echo -e "生成 4096 位 RSA 密钥对..."
        ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N ""
        cat /root/.ssh/id_rsa.pub >> "$AUTH_KEYS"
        chmod 600 "$AUTH_KEYS"
        echo -e "${GREEN}密钥对已生成！请立即下载私钥: /root/.ssh/id_rsa${NC}"
    fi

    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin without-password/' $SSH_CONF
    sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' $SSH_CONF
    sed -i 's/^#\?AuthorizedKeysFile.*/AuthorizedKeysFile .ssh\/authorized_keys/' $SSH_CONF
    
    read -p "是否禁用密码登录？(y/n): " dis_pwd
    [[ "$dis_pwd" =~ ^[Yy]$ ]] && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' $SSH_CONF
    
    restart_service
}

# --- 5. 功能：修改端口 (含防火墙/SELinux 联动) ---
change_port() {
    echo -e "\n${YELLOW}[操作] 修改/新增 SSH 端口...${NC}"
    read -p "请输入新端口号 (1-65535): " new_port
    [[ ! "$new_port" =~ ^[0-9]+$ ]] && echo "无效输入" && return

    # 修改配置逻辑
    read -p "模式: [A]追加(保留22) | [R]替换(仅新端口): " p_mode
    if [[ "$p_mode" =~ ^[Aa]$ ]]; then
        sed -i 's/^#Port 22/Port 22/' $SSH_CONF
        grep -q "^Port $new_port" $SSH_CONF || sed -i "/^Port 22/a Port $new_port" $SSH_CONF
    else
        sed -i "s/^#\?Port.*/Port $new_port/" $SSH_CONF
    fi

    # A. 处理防火墙
    if command -v ufw >/dev/null; then
        ufw allow "$new_port"/tcp
    elif command -v firewall-cmd >/dev/null; then
        firewall-cmd --permanent --add-port="$new_port"/tcp
        firewall-cmd --reload
    fi

    # B. 处理 SELinux (关键步骤)
    if [[ "$SELINUX_STATE" == "Enforcing" ]]; then
        echo "检测到 SELinux 开启，正在尝试添加端口策略..."
        if command -v semanage >/dev/null; then
            semanage port -a -t ssh_port_t -p tcp "$new_port"
        else
            echo -e "${RED}警告: 未找到 semanage 命令，请手动安装 policycoreutils-python 以支持 SELinux 端口修改${NC}"
        fi
    fi

    restart_service
}

# --- 6. 功能：修改时区 ---
change_timezone() {
    echo -e "\n${YELLOW}[操作] 修改系统时区为 Asia/Shanghai...${NC}"
    echo -e "当前时区: ${BLUE}$CURRENT_TIMEZONE${NC}"
    
    if [[ "$CURRENT_TIMEZONE" == "Asia/Shanghai" ]]; then
        echo -e "${GREEN}时区已经是 Asia/Shanghai，无需修改。${NC}"
        return
    fi
    
    read -p "确认将时区修改为 Asia/Shanghai？(y/n): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}操作已取消。${NC}"
        return
    fi
    
    # 优先使用 timedatectl
    if command -v timedatectl >/dev/null 2>&1; then
        echo -e "${BLUE}使用 timedatectl 设置时区...${NC}"
        if timedatectl set-timezone Asia/Shanghai 2>/dev/null; then
            echo -e "${GREEN}时区设置成功！${NC}"
            detect_os  # 刷新时区变量
            return
        fi
    fi
    
    # 回退到传统方法
    echo -e "${BLUE}使用传统方法设置时区...${NC}"
    if [ -f /usr/share/zoneinfo/Asia/Shanghai ]; then
        ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}时区设置成功！${NC}"
            detect_os  # 刷新时区变量
        else
            echo -e "${RED}时区设置失败，请检查权限或手动设置。${NC}"
        fi
    else
        echo -e "${RED}错误: 未找到 Asia/Shanghai 时区文件。${NC}"
    fi
}

# =============================================================================
# SS 相关功能模块
# =============================================================================

# 获取最新版本
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
    
    # 配置防火墙
    if command -v ufw >/dev/null 2>&1; then
        ufw allow ${SS_PORT}/tcp >/dev/null 2>&1
        ufw allow ${SS_PORT}/udp >/dev/null 2>&1
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port=${SS_PORT}/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=${SS_PORT}/udp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    elif command -v iptables >/dev/null 2>&1; then
        iptables -I INPUT -p tcp --dport ${SS_PORT} -j ACCEPT 2>/dev/null
        iptables -I INPUT -p udp --dport ${SS_PORT} -j ACCEPT 2>/dev/null
    fi
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

# --- 安装中文字体和 Locale ---
install_chinese_support() {
    echo -e "\n${YELLOW}[操作] 正在安装中文字体和 Locale...${NC}"
    
    # 根据系统类型安装软件包
    if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
        echo -e "${BLUE}检测到 Debian/Ubuntu 系统，正在安装软件包...${NC}"
        apt-get update && apt-get install -y locales language-pack-zh-hans fonts-wqy-zenhei fonts-wqy-microhei ttf-wqy-zenhei xfonts-wqy
        if [ $? -ne 0 ]; then
            echo -e "${RED}错误: 软件包安装失败，请检查网络或软件源配置${NC}"
            return 1
        fi
    else
        echo -e "${BLUE}检测到 CentOS/RHEL 系统，正在安装软件包...${NC}"
        # 兼容 CentOS 7 (glibc-common) 和 CentOS 8+ (glibc-langpack-zh)
        yum install -y glibc-langpack-zh glibc-common wqy-zenhei-fonts wqy-microhei-fonts 2>/dev/null || true
    fi
    
    # 检查并创建配置文件
    [ ! -f /etc/environment ] && touch /etc/environment
    [ ! -f /etc/profile ] && touch /etc/profile
    
    # 配置 /etc/environment
    echo -e "${BLUE}配置 /etc/environment...${NC}"
    if ! grep -q "^LANG=" /etc/environment; then
        echo 'LANG="zh_CN.UTF-8"' >> /etc/environment
        echo -e "${GREEN}已添加 LANG 配置${NC}"
    else
        echo -e "${YELLOW}LANG 配置已存在，跳过${NC}"
    fi
    
    if ! grep -q "^LANGUAGE=" /etc/environment; then
        echo 'LANGUAGE="zh_CN:zh:en_US:en"' >> /etc/environment
        echo -e "${GREEN}已添加 LANGUAGE 配置${NC}"
    else
        echo -e "${YELLOW}LANGUAGE 配置已存在，跳过${NC}"
    fi
    
    # 配置 /etc/profile
    echo -e "${BLUE}配置 /etc/profile...${NC}"
    if ! grep -q "export LANG=" /etc/profile; then
        echo 'export LANG=zh_CN.UTF-8' >> /etc/profile
        echo -e "${GREEN}已添加 export LANG${NC}"
    else
        echo -e "${YELLOW}export LANG 已存在，跳过${NC}"
    fi
    
    if ! grep -q "export LANGUAGE=" /etc/profile; then
        echo 'export LANGUAGE=zh_CN:zh' >> /etc/profile
        echo -e "${GREEN}已添加 export LANGUAGE${NC}"
    else
        echo -e "${YELLOW}export LANGUAGE 已存在，跳过${NC}"
    fi
    
    # 执行 locale 生成
    echo -e "${BLUE}生成中文 Locale...${NC}"
    if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
        locale-gen zh_CN.UTF-8
        update-locale LANG=zh_CN.UTF-8
    else
        localectl set-locale LANG=zh_CN.UTF-8
    fi
    
    # 立即生效当前会话
    export LANG=zh_CN.UTF-8
    export LANGUAGE=zh_CN:zh
    
    # 验证 Locale 是否成功生成
    echo -e "${BLUE}验证中文 Locale...${NC}"
    if ! locale -a 2>/dev/null | grep -qi "zh_CN"; then
        echo -e "${YELLOW}警告: 中文 Locale 可能未成功生成，请执行 locale -a 手动检查${NC}"
    else
        echo -e "${GREEN}中文 Locale 验证成功${NC}"
    fi
    
    # 显示成功信息
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}中文字体和 Locale 安装完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "当前 Locale 设置:"
    locale 2>/dev/null | grep "^LANG=" || echo "LANG=zh_CN.UTF-8 (已配置)"
    echo -e "\n${YELLOW}提示:${NC}"
    echo -e "  • 当前会话已生效"
    echo -e "  • 新会话请重新登录或执行: ${GREEN}source /etc/profile${NC}"
    echo -e "  • Windows PuTTY 用户请在 窗口→翻译 中设置字符集为 UTF-8"
    echo -e "${GREEN}========================================${NC}\n"
}

# SS 管理二级菜单
ss_menu() {
    while true; do
        clear
        detect_os
        echo -e "${BLUE}=============== SS 管理菜单 ===============${NC}"
        
        # 默认显示配置信息（不显示二维码）
        if [[ -f "$BINARY_PATH" && -f "$CONFIG_PATH" ]]; then
            view_ss_config false
            
            # 显示服务状态
            if systemctl is-active ss >/dev/null 2>&1; then
                echo -e "服务状态: ${GREEN}运行中${NC}"
            else
                echo -e "服务状态: ${RED}未运行${NC}"
            fi
        else
            echo -e "\n${RED}SS 未安装${NC}\n"
        fi
        
        echo -e "${BLUE}===========================================${NC}"
        echo "1) 安装/重置 SS"
        echo "2) 查看完整配置（含二维码）"
        echo "3) 卸载 SS"
        echo "b) 返回主菜单"
        read -p "选择操作: " opt
        case $opt in
            1) install_ss true false; read -n 1 -p "按任意键继续..." ;;
            2) view_ss_config true; read -n 1 -p "按任意键继续..." ;;
            3) uninstall_ss; read -n 1 -p "按任意键继续..." ;;
            b|B) break ;;
            *) echo "无效选项"; sleep 1 ;;
        esac
    done
}

# --- 命令行参数处理 ---
if [[ "$1" == "ss" && "$2" == "config" ]]; then
    detect_os
    view_ss_config false
    exit 0
elif [[ "$1" == "ss" && "$2" == "auto" ]]; then
    check_root
    detect_os
    install_ss false true  # 不显示二维码，自动确认（非交互模式）
    exit 0
fi

# --- 主程序循环 ---
check_root
while true; do
    check_status
    echo "1) SS 管理"
    echo "2) 一键启用 Root 密钥登录"
    echo "3) 修改或新增 SSH 端口"
    echo "4) 修改系统时区为 Asia/Shanghai"
    echo "5) 安装中文字体和 Locale"
    echo "q) 退出"
    read -p "选择操作: " opt
    case $opt in
        1) ss_menu ;;
        2) enable_key_login; read -n 1 -p "按任意键继续..." ;;
        3) change_port; read -n 1 -p "按任意键继续..." ;;
        4) change_timezone; read -n 1 -p "按任意键继续..." ;;
        5) install_chinese_support; read -n 1 -p "按任意键继续..." ;;
        q) exit 0 ;;
        *) echo "无效选项" ;;
    esac
done