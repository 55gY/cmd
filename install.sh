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
IS_64BIT=""

# --- 工具函数 ---
# 版本号比较（大于等于）
_version_ge() {
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
}

# 检查命令是否存在
_exists() {
    local cmd="$1"
    if eval type type > /dev/null 2>&1; then
        eval type "$cmd" > /dev/null 2>&1
    elif command > /dev/null 2>&1; then
        command -v "$cmd" > /dev/null 2>&1
    else
        which "$cmd" > /dev/null 2>&1
    fi
    local rt=$?
    return ${rt}
}

# 检测是否为数字
_is_digit() {
    local input=${1}
    if [[ "$input" =~ ^[0-9]+$ ]]; then
        return 0
    else
        return 1
    fi
}

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
    
    # 检测是否为 64 位系统
    IS_64BIT="false"
    if [ $(getconf WORD_BIT 2>/dev/null) = '32' ] && [ $(getconf LONG_BIT 2>/dev/null) = '64' ]; then
        IS_64BIT="true"
    fi
    
    # 检测虚拟化环境
    VIRT_TYPE="none"
    if _exists "systemd-detect-virt"; then
        VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "none")
    elif _exists "virt-what"; then
        VIRT_TYPE=$(virt-what 2>/dev/null || echo "none")
    fi
    [ -d "/proc/vz" ] && VIRT_TYPE="openvz"
    
    # 检测 BBR 状态
    BBR_STATUS="未启用"
    local bbr_param=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    if [[ "x${bbr_param}" == "xbbr" ]]; then
        BBR_STATUS="已启用"
    fi
    
    # 检测内核版本
    KERNEL_VERSION=$(uname -r | cut -d- -f1)
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
    
    # BBR 状态显示
    if [[ "$BBR_STATUS" == "已启用" ]]; then
        echo -e "BBR 加速      : ${GREEN}已启用${NC} (内核 ${KERNEL_VERSION})"
    else
        echo -e "BBR 加速      : ${RED}未启用${NC} (内核 ${KERNEL_VERSION})"
    fi
    
    echo -e "${BLUE}=====================================================${NC}"
}

# --- 3. SSH 配置辅助函数 ---
# 修改SSH配置项（支持模块化配置目录）
set_ssh_config() {
    local key="$1"
    local value="$2"
    local pattern="^#\\?${key}"
    
    # 检查是否存在 sshd_config.d 目录
    local config_dir="/etc/ssh/sshd_config.d"
    local cloud_config=""
    
    # 查找云平台配置文件
    if [ -d "$config_dir" ]; then
        # AWS, Google Cloud 等常见配置文件
        for conf_file in "60-cloudimg-settings.conf" "50-cloud-init.conf" "99-cloudimg-settings.conf"; do
            if [ -f "$config_dir/$conf_file" ]; then
                cloud_config="$config_dir/$conf_file"
                echo -e "${BLUE}  检测到云平台配置: $conf_file${NC}"
                # 修改云平台配置文件
                if grep -q "$pattern" "$cloud_config"; then
                    sed -i "s/$pattern.*/${key} ${value}/" "$cloud_config"
                    echo -e "${GREEN}  ✓ 已更新 $conf_file 中的 $key${NC}"
                fi
            fi
        done
    fi
    
    # 同时修改主配置文件
    if grep -q "$pattern" "$SSH_CONF"; then
        sed -i "s/$pattern.*/${key} ${value}/" "$SSH_CONF"
    else
        echo "${key} ${value}" >> "$SSH_CONF"
    fi
    echo -e "${GREEN}  ✓ 已更新主配置文件中的 $key${NC}"
}

# 重启 SSH 服务 (兼容多系统)
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

    # 检查是否存在云平台的root登录限制
    if [ -f "$AUTH_KEYS" ] && grep -q 'command=".*Please login as the user.*rather than.*root' "$AUTH_KEYS"; then
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${RED}检测到云平台的 root 登录限制！${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}当前 authorized_keys 包含阻止 root 登录的命令${NC}"
        echo -e "${BLUE}示例: command=\"echo 'Please login...'\"${NC}"
        echo ""
        read -p "是否清理此限制以允许 root 登录？(y/n): " clean_restriction
        
        if [[ "$clean_restriction" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}正在清理云平台限制...${NC}"
            
            # 备份原文件
            local backup_file="${AUTH_KEYS}.bak.$(date +%Y%m%d%H%M%S)"
            cp "$AUTH_KEYS" "$backup_file"
            echo -e "${GREEN}✓ 已备份到: $backup_file${NC}"
            
            # 使用sed清理：移除所有选项前缀，只保留密钥类型开始的部分
            sed -i 's/^.*\(ssh-rsa\|ssh-ed25519\|ecdsa-sha2-nistp[0-9]\+\|ssh-dss\)/\1/' "$AUTH_KEYS"
            
            echo -e "${GREEN}✓ 已清理云平台限制${NC}"
            echo -e "${YELLOW}提示: 如需恢复，备份文件: $backup_file${NC}"
        else
            echo -e "${YELLOW}跳过清理，保留原有限制${NC}"
            echo -e "${RED}注意: 保留限制可能导致无法使用 root 登录！${NC}"
        fi
    fi

    # 判断是否需要生成新密钥
    local need_new_key=false
    if [ ! -f "$AUTH_KEYS" ]; then
        need_new_key=true
        echo -e "${YELLOW}密钥文件不存在，将生成新密钥对...${NC}"
    else
        echo -e "${BLUE}密钥文件已存在 (包含 $(wc -l < $AUTH_KEYS 2>/dev/null || echo "0") 个密钥)${NC}"
        read -p "是否添加新的密钥对？(y/n): " add_key
        [[ "$add_key" =~ ^[Yy]$ ]] && need_new_key=true
    fi

    if [ "$need_new_key" = true ]; then
        echo -e "${BLUE}生成 4096 位 RSA 密钥对...${NC}"
        local key_name="/root/.ssh/id_rsa"
        
        # 如果已存在，使用新文件名
        if [ -f "$key_name" ]; then
            key_name="/root/.ssh/id_rsa_$(date +%Y%m%d%H%M%S)"
            echo -e "${YELLOW}检测到已存在密钥，使用新文件名: $(basename $key_name)${NC}"
        fi
        
        ssh-keygen -t rsa -b 4096 -f "$key_name" -N "" -C "root@$(hostname)"
        
        if [ $? -eq 0 ]; then
            cat "${key_name}.pub" >> "$AUTH_KEYS"
            chmod 600 "$AUTH_KEYS"
            echo -e "${GREEN}✓ 密钥对已生成${NC}"
            echo -e "${GREEN}✓ 公钥已添加到 authorized_keys${NC}"
            echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "${RED}重要: 请立即下载私钥文件！${NC}"
            echo -e "${RED}私钥路径: $key_name${NC}"
            echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        else
            echo -e "${RED}密钥生成失败！${NC}"
            return 1
        fi
    fi

    # 配置 SSH
    echo -e "${BLUE}配置 SSH 服务...${NC}"
    set_ssh_config "PermitRootLogin" "yes"
    set_ssh_config "PubkeyAuthentication" "yes"
    set_ssh_config "AuthorizedKeysFile" ".ssh/authorized_keys"
    
    # 检查当前密码登录状态
    local current_pwd_auth=""
    local config_dir="/etc/ssh/sshd_config.d"
    
    # 首先检查云平台配置文件
    if [ -d "$config_dir" ]; then
        for conf_file in "60-cloudimg-settings.conf" "50-cloud-init.conf" "99-cloudimg-settings.conf"; do
            if [ -f "$config_dir/$conf_file" ]; then
                local cloud_pwd=$(grep "^PasswordAuthentication" "$config_dir/$conf_file" 2>/dev/null | awk '{print $2}')
                if [ -n "$cloud_pwd" ]; then
                    current_pwd_auth="$cloud_pwd"
                    break
                fi
            fi
        done
    fi
    
    # 如果云平台配置中没有，检查主配置文件
    if [ -z "$current_pwd_auth" ]; then
        current_pwd_auth=$(grep "^PasswordAuthentication" "$SSH_CONF" 2>/dev/null | awk '{print $2}')
    fi
    
    # 如果还是没找到，默认为yes
    [ -z "$current_pwd_auth" ] && current_pwd_auth="yes"
    
    # 询问是否禁用密码登录
    echo -e "\n${BLUE}当前密码登录状态: ${YELLOW}$current_pwd_auth${NC}"
    
    if [[ "$current_pwd_auth" == "no" ]]; then
        echo -e "${GREEN}密码登录已禁用，安全性较高${NC}"
    else
        echo -e "${YELLOW}建议禁用密码登录以提高安全性${NC}"
        echo -e "${RED}警告: 禁用后只能使用密钥登录，请确保已下载私钥！${NC}"
        read -p "是否禁用密码登录？(y/n): " dis_pwd
        
        if [[ "$dis_pwd" =~ ^[Yy]$ ]]; then
            set_ssh_config "PasswordAuthentication" "no"
            echo -e "${GREEN}已禁用密码登录${NC}"
        else
            echo -e "${YELLOW}已保留密码登录${NC}"
        fi
    fi
    
    # 显示当前 authorized_keys 内容（仅显示前几个字符）
    echo -e "\n${BLUE}当前 authorized_keys 内容:${NC}"
    if [ -f "$AUTH_KEYS" ]; then
        awk '{print NR". " substr($1,1,20)"... " substr($2,1,30)"... " $3}' "$AUTH_KEYS"
    fi
    
    restart_service
    
    echo -e "\n${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}        Root 密钥登录配置完成！       ${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}下一步操作:${NC}"
    echo -e "  1. 下载私钥文件到本地"
    echo -e "  2. 设置私钥权限: ${GREEN}chmod 600 私钥文件${NC}"
    echo -e "  3. 使用私钥登录: ${GREEN}ssh -i 私钥文件 root@服务器IP${NC}"
    echo -e "${RED}  4. 确认密钥登录成功后，再断开当前会话！${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

# --- 5. 功能：修改端口 (含防火墙/SELinux 联动) ---
change_port() {
    # 确保系统变量已初始化
    detect_os
    
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
        apt-get update && apt-get install -y locales language-pack-zh-hans language-pack-zh-hans-base \
            fonts-wqy-zenhei fonts-wqy-microhei ttf-wqy-zenhei xfonts-wqy manpages-zh
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
    
    # 重新配置相关系统包以应用语言设置（Ubuntu特有）
    if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
        echo -e "${BLUE}重新配置系统组件以应用中文...${NC}"
        dpkg-reconfigure -f noninteractive locales 2>/dev/null || true
    fi
    
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
    echo -e "  • ${RED}必须完全退出并重新登录${NC}才能使系统欢迎信息显示中文"
    echo -e "  • 执行 ${GREEN}exit${NC} 退出，然后重新 SSH 登录"
    echo -e "  • Windows PuTTY 用户请在 窗口→翻译 中设置字符集为 UTF-8"
    echo -e "${GREEN}========================================${NC}\n"
}

# =============================================================================
# BBR 加速相关功能模块
# =============================================================================

# 检查 BBR 状态
check_bbr_status() {
    local param=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    if [[ "x${param}" == "xbbr" ]]; then
        return 0
    else
        return 1
    fi
}

# 检查内核版本（BBR 需要 4.9+）
check_kernel_version() {
    local kernel_version=$(uname -r | cut -d- -f1)
    if _version_ge ${kernel_version} 4.9; then
        return 0
    else
        return 1
    fi
}

# 检查系统兼容性
check_bbr_os() {
    # 检查虚拟化环境
    if [[ "$VIRT_TYPE" == "lxc" ]]; then
        echo -e "${RED}错误: 检测到 LXC 虚拟化环境，不支持内核升级${NC}"
        return 1
    fi
    if [[ "$VIRT_TYPE" == "openvz" ]]; then
        echo -e "${RED}错误: 检测到 OpenVZ 虚拟化环境，不支持内核升级${NC}"
        return 1
    fi
    
    # 检查操作系统版本
    case "$OS_ID" in
        ubuntu)
            if [ -f /etc/os-release ]; then
                local ver=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2 | cut -d'.' -f1)
                if [ -n "$ver" ] && [ "$ver" -lt 16 ]; then
                    echo -e "${RED}不支持的系统版本，请升级到 Ubuntu 16+ 后重试${NC}"
                    return 1
                fi
            fi
            ;;
        debian)
            if [ -f /etc/os-release ]; then
                local ver=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2 | cut -d'.' -f1)
                if [ -n "$ver" ] && [ "$ver" -lt 8 ]; then
                    echo -e "${RED}不支持的系统版本，请升级到 Debian 8+ 后重试${NC}"
                    return 1
                fi
            fi
            ;;
        centos|rhel)
            if [ -f /etc/os-release ]; then
                local ver=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2 | cut -d'.' -f1)
                if [ -n "$ver" ] && [ "$ver" -lt 6 ]; then
                    echo -e "${RED}不支持的系统版本，请升级到 CentOS 6+ 后重试${NC}"
                    return 1
                fi
            fi
            ;;
        *)
            echo -e "${YELLOW}警告: 未识别的操作系统类型，可能不受支持${NC}"
            ;;
    esac
    
    return 0
}

# 配置 BBR sysctl 参数
sysctl_config() {
    echo -e "${BLUE}配置 BBR 参数...${NC}"
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
    echo -e "${GREEN}✓ BBR 参数配置完成${NC}"
}

# 安装内核
install_kernel() {
    case "$OS_ID" in
        centos|rhel)
            echo -e "${BLUE}检测到 CentOS/RHEL 系统${NC}"
            if [ -f /etc/os-release ]; then
                local ver=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2 | cut -d'.' -f1)
                
                # 检查 perl 依赖
                if ! _exists "perl"; then
                    echo -e "${BLUE}安装 perl 依赖...${NC}"
                    yum install -y perl
                fi
                
                if [ "$ver" == "6" ]; then
                    echo -e "${BLUE}为 CentOS 6 安装内核 4.18.20...${NC}"
                    rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org 2>/dev/null || true
                    
                    local rpm_kernel_url="https://dl.lamp.sh/files/"
                    if [[ "$IS_64BIT" == "true" ]]; then
                        local rpm_kernel_name="kernel-ml-4.18.20-1.el6.elrepo.x86_64.rpm"
                        local rpm_kernel_devel_name="kernel-ml-devel-4.18.20-1.el6.elrepo.x86_64.rpm"
                    else
                        local rpm_kernel_name="kernel-ml-4.18.20-1.el6.elrepo.i686.rpm"
                        local rpm_kernel_devel_name="kernel-ml-devel-4.18.20-1.el6.elrepo.i686.rpm"
                    fi
                    
                    wget -c -t3 -T60 -O ${rpm_kernel_name} ${rpm_kernel_url}${rpm_kernel_name}
                    wget -c -t3 -T60 -O ${rpm_kernel_devel_name} ${rpm_kernel_url}${rpm_kernel_devel_name}
                    
                    if [ -s "${rpm_kernel_name}" ]; then
                        rpm -ivh ${rpm_kernel_name} || { echo -e "${RED}内核安装失败${NC}"; return 1; }
                    else
                        echo -e "${RED}内核下载失败${NC}"
                        return 1
                    fi
                    
                    if [ -s "${rpm_kernel_devel_name}" ]; then
                        rpm -ivh ${rpm_kernel_devel_name} || true
                    fi
                    
                    rm -f ${rpm_kernel_name} ${rpm_kernel_devel_name}
                    
                    if [ -f "/boot/grub/grub.conf" ]; then
                        sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
                    fi
                    
                elif [ "$ver" == "7" ]; then
                    echo -e "${BLUE}为 CentOS 7 安装内核 5.15.60...${NC}"
                    
                    if [[ "$IS_64BIT" != "true" ]]; then
                        echo -e "${RED}CentOS 7 仅支持 64 位架构${NC}"
                        return 1
                    fi
                    
                    local rpm_kernel_url="https://dl.lamp.sh/kernel/el7/"
                    local rpm_kernel_name="kernel-ml-5.15.60-1.el7.x86_64.rpm"
                    local rpm_kernel_devel_name="kernel-ml-devel-5.15.60-1.el7.x86_64.rpm"
                    
                    wget -c -t3 -T60 -O ${rpm_kernel_name} ${rpm_kernel_url}${rpm_kernel_name}
                    wget -c -t3 -T60 -O ${rpm_kernel_devel_name} ${rpm_kernel_url}${rpm_kernel_devel_name}
                    
                    if [ -s "${rpm_kernel_name}" ]; then
                        rpm -ivh ${rpm_kernel_name} || { echo -e "${RED}内核安装失败${NC}"; return 1; }
                    else
                        echo -e "${RED}内核下载失败${NC}"
                        return 1
                    fi
                    
                    if [ -s "${rpm_kernel_devel_name}" ]; then
                        rpm -ivh ${rpm_kernel_devel_name} || true
                    fi
                    
                    rm -f ${rpm_kernel_name} ${rpm_kernel_devel_name}
                    /usr/sbin/grub2-set-default 0
                else
                    echo -e "${YELLOW}CentOS 8+ 系统通常已包含 4.9+ 内核，建议直接启用 BBR${NC}"
                    return 1
                fi
            fi
            ;;
        ubuntu|debian)
            echo -e "${BLUE}检测到 Ubuntu/Debian 系统${NC}"
            echo -e "${YELLOW}正在从 Ubuntu Mainline 获取最新内核列表...${NC}"
            
            # 获取内核版本列表
            local latest_version=($(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/ | awk -F'"v' '/v[4-9]./{print $2}' | cut -d/ -f1 | grep -v - | sort -V))
            
            if [ ${#latest_version[@]} -eq 0 ]; then
                echo -e "${RED}获取内核版本列表失败${NC}"
                return 1
            fi
            
            # 筛选 5.15+ 版本
            local kernel_arr=()
            for i in ${latest_version[@]}; do
                if _version_ge $i 5.15; then
                    kernel_arr+=($i)
                fi
            done
            
            if [ ${#kernel_arr[@]} -eq 0 ]; then
                echo -e "${RED}未找到符合条件的内核版本（≥5.15）${NC}"
                return 1
            fi
            
            # 选择最新版本
            local kernel=${kernel_arr[-1]}
            echo -e "${GREEN}选择内核版本: ${kernel}${NC}"
            
            # 下载内核
            local deb_name deb_modules_name
            if [[ "$IS_64BIT" == "true" ]]; then
                deb_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-image" | grep "generic" | awk -F'">' '/amd64.deb/{print $2}' | cut -d'<' -f1 | head -1)
                deb_modules_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-modules" | grep "generic" | awk -F'">' '/amd64.deb/{print $2}' | cut -d'<' -f1 | head -1)
            else
                deb_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-image" | grep "generic" | awk -F'">' '/i386.deb/{print $2}' | cut -d'<' -f1 | head -1)
                deb_modules_name=$(wget -qO- https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/ | grep "linux-modules" | grep "generic" | awk -F'">' '/i386.deb/{print $2}' | cut -d'<' -f1 | head -1)
            fi
            
            if [ -z "${deb_name}" ]; then
                echo -e "${RED}获取内核包名称失败，该内核可能构建失败${NC}"
                return 1
            fi
            
            local deb_kernel_url="https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${deb_name}"
            local deb_kernel_modules_url="https://kernel.ubuntu.com/~kernel-ppa/mainline/v${kernel}/${deb_modules_name}"
            
            echo -e "${BLUE}下载内核包...${NC}"
            cd /tmp
            
            if [ -n "${deb_modules_name}" ]; then
                wget -c -t3 -T60 -O "${deb_modules_name}" "${deb_kernel_modules_url}" || { echo -e "${RED}模块包下载失败${NC}"; return 1; }
            fi
            
            wget -c -t3 -T60 -O "${deb_name}" "${deb_kernel_url}" || { echo -e "${RED}内核包下载失败${NC}"; return 1; }
            
            echo -e "${BLUE}安装内核包...${NC}"
            dpkg -i ${deb_modules_name} ${deb_name} || { echo -e "${RED}内核安装失败${NC}"; return 1; }
            
            rm -f ${deb_modules_name} ${deb_name}
            /usr/sbin/update-grub
            ;;
        *)
            echo -e "${RED}不支持的操作系统${NC}"
            return 1
            ;;
    esac
    
    echo -e "${GREEN}✓ 内核安装完成${NC}"
    return 0
}

# 系统网络优化配置
add_system_optimization() {
    echo -e "\n${BLUE}开始应用系统网络优化配置...${NC}"
    
    # 备份原配置
    if [ -f /etc/sysctl.conf ]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d%H%M%S)
        echo -e "${GREEN}✓ 已备份 sysctl.conf${NC}"
    fi
    
    # 添加优化参数
    cat >> /etc/sysctl.conf <<-EOF

# BBR 系统网络优化配置 (添加于 $(date +%Y-%m-%d))
fs.file-max = 1000000
fs.inotify.max_user_instances = 8192

net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.route.gc_timeout = 100

net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_orphans = 32768

# forward ipv4 (取消注释以启用)
#net.ipv4.ip_forward = 1

EOF

    # 配置文件描述符限制
    if [ -f /etc/security/limits.conf ]; then
        if ! grep -q "^\*.*nofile.*1000000" /etc/security/limits.conf; then
            cat >> /etc/security/limits.conf <<-EOF
# BBR 优化 - 文件描述符限制
*               soft    nofile          1000000
*               hard    nofile          1000000
EOF
            echo -e "${GREEN}✓ 已配置文件描述符限制${NC}"
        else
            echo -e "${YELLOW}文件描述符限制已存在，跳过${NC}"
        fi
    fi
    
    # 配置 profile
    if ! grep -q "ulimit -SHn 1000000" /etc/profile; then
        echo "ulimit -SHn 1000000" >> /etc/profile
        echo -e "${GREEN}✓ 已配置 ulimit${NC}"
    else
        echo -e "${YELLOW}ulimit 配置已存在，跳过${NC}"
    fi
    
    # 应用配置
    sysctl -p >/dev/null 2>&1
    source /etc/profile 2>/dev/null || true
    
    echo -e "${GREEN}✓ 系统网络优化配置完成${NC}"
}

# 主 BBR 启用函数
enable_bbr() {
    echo -e "\n${BLUE}===========================================${NC}"
    echo -e "${BLUE}      启用 TCP BBR 加速 + 系统优化       ${NC}"
    echo -e "${BLUE}===========================================${NC}\n"
    
    # 刷新系统信息
    detect_os
    
    # 1. 检查是否已启用
    if check_bbr_status; then
        echo -e "${GREEN}TCP BBR 已经启用！${NC}"
        echo -e "当前拥塞控制算法: ${YELLOW}$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')${NC}"
        echo -e "当前队列算法: ${YELLOW}$(sysctl net.core.default_qdisc | awk '{print $3}')${NC}"
        echo -e "\n${YELLOW}是否继续应用系统网络优化配置？(y/n): ${NC}"
        read -p "请选择: " apply_opt
        if [[ "$apply_opt" =~ ^[Yy]$ ]]; then
            add_system_optimization
        fi
        return 0
    fi
    
    echo -e "${YELLOW}当前 BBR 状态: 未启用${NC}"
    echo -e "当前内核版本: ${YELLOW}$(uname -r)${NC}\n"
    
    # 2. 检查内核版本
    if check_kernel_version; then
        echo -e "${GREEN}✓ 内核版本满足要求（≥4.9），可直接启用 BBR${NC}\n"
        
        read -p "是否立即启用 BBR 并应用系统优化？(y/n): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}操作已取消${NC}"
            return 0
        fi
        
        sysctl_config
        add_system_optimization
        
        # 验证
        if check_bbr_status; then
            echo -e "\n${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "${GREEN}  TCP BBR 启用成功！${NC}"
            echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "当前拥塞控制: ${YELLOW}$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')${NC}"
            echo -e "当前队列算法: ${YELLOW}$(sysctl net.core.default_qdisc | awk '{print $3}')${NC}"
            echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
        else
            echo -e "${RED}BBR 启用失败，请检查系统日志${NC}"
        fi
        
        return 0
    fi
    
    # 3. 需要升级内核
    echo -e "${YELLOW}当前内核版本 < 4.9，需要升级内核以支持 BBR${NC}\n"
    
    # 检查系统兼容性
    if ! check_bbr_os; then
        return 1
    fi
    
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}       警告：内核升级存在风险！        ${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}内核升级后如果不兼容可能导致系统无法启动${NC}"
    echo -e "${YELLOW}建议先在测试环境或虚拟机中验证${NC}"
    echo -e "${YELLOW}虚拟化类型: ${VIRT_TYPE}${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    
    read -p "确认要升级内核并启用 BBR？(yes/no): " confirm_kernel
    if [[ "$confirm_kernel" != "yes" ]]; then
        echo -e "${YELLOW}操作已取消${NC}"
        return 0
    fi
    
    # 安装内核
    echo -e "\n${BLUE}开始安装新内核...${NC}"
    if ! install_kernel; then
        echo -e "${RED}内核安装失败${NC}"
        return 1
    fi
    
    # 配置 BBR
    sysctl_config
    
    # 应用系统优化
    add_system_optimization
    
    # 询问重启
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}    内核安装完成，需要重启系统生效    ${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}重启后 BBR 将自动启用${NC}\n"
    
    read -p "是否立即重启系统？(y/n): " is_reboot
    if [[ "$is_reboot" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}系统将在 3 秒后重启...${NC}"
        sleep 3
        reboot
    else
        echo -e "${YELLOW}已取消重启，请稍后手动执行 reboot 命令${NC}"
        echo -e "${YELLOW}重启后执行 sysctl net.ipv4.tcp_congestion_control 验证 BBR 状态${NC}"
    fi
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
    echo "1. SS 管理"
    echo "2. 启用 TCP BBR 加速 + 系统网络优化"
    echo "3. 一键启用 Root 密钥登录"
    echo "4. 修改或新增 SSH 端口"
    echo "5. 修改系统时区为 Asia/Shanghai"
    echo "6. 安装中文字体和 Locale"
    echo "0. 退出"
    read -p "选择操作: " opt
    case $opt in
        1) ss_menu ;;
        2) enable_bbr; read -n 1 -p "按任意键继续..." ;;
        3) enable_key_login; read -n 1 -p "按任意键继续..." ;;
        4) change_port; read -n 1 -p "按任意键继续..." ;;
        5) change_timezone; read -n 1 -p "按任意键继续..." ;;
        6) install_chinese_support; read -n 1 -p "按任意键继续..." ;;
        0) exit 0 ;;
        *) echo "无效选项" ;;
    esac
done