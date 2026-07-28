#!/bin/bash
# ============================================================
# common.sh  —  共用依赖: 颜色/全局变量、权限与系统检测、状态面板
# 被 install.sh 加载; 各功能模块(modules/*.sh)依赖本文件提供的变量与函数。
# 运行 install.sh 时随即加载, 保证无需下载任何模块即可显示全部功能状态。
# ============================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'
GREEN_BOLD='\033[1;32m'
RED_BOLD='\033[1;31m'

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

# Mihomo 相关配置
LOG_DIR="/var/log/ATAsst"
INSTALL_LOG="$LOG_DIR/mihomo_install.log"
CORE_BIN="/usr/local/bin/mihomo"
SERVICE_FILE="/etc/systemd/system/mihomo.service"
CONFIG_DIR="/etc/mihomo"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
AI_MODEL_PATH="$CONFIG_DIR/Model.bin"
PURPLE='\033[0;35m'
CYAN='\033[0;36m'

# Reality (VLESS) 相关路径
REALITY_CONFIG="${REALITY_CONFIG:-/usr/local/etc/xray/config.json}"
REALITY_BIN="${REALITY_BIN:-$(command -v xray 2>/dev/null || echo /usr/local/bin/xray)}"

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

# ---------- 统一状态面板样式 + 共用状态检测 (各模块详情面板共用) ----------
panel_top() { echo -e "${BLUE}========== $1 ==========${NC}"; }
panel_bot() { echo -e "${BLUE}========================================${NC}"; }

# 服务状态(带颜色字符串): 运行中 / 已停止 / 未安装
svc_status_str() {
    local svc="$1"
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "${GREEN_BOLD}运行中 (active)${NC}"; return
        fi
        if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
            echo -e "${YELLOW}已停止 (inactive)${NC}"; return
        fi
    fi
    echo -e "${RED_BOLD}未安装/未运行${NC}"
}

# 端口监听(带颜色): 监听中 / 未监听 / 未知
port_listen_str() {
    local port="$1"
    [[ -z "$port" ]] && { echo -e "${YELLOW}未知${NC}"; return; }
    if command -v ss >/dev/null 2>&1; then
        if ss -ltn "sport = :${port}" 2>/dev/null | grep -q "LISTEN"; then
            echo -e "${GREEN_BOLD}监听中${NC}"
        else
            echo -e "${RED_BOLD}未监听${NC}"
        fi
    else
        echo -e "${YELLOW}未知(缺 ss)${NC}"
    fi
}

# 各代理端口解析 (集中, 主面板与详情面板共用)
ss_get_port() { [[ -f "$CONFIG_PATH" ]] && grep -oP '"server_port"\s*:\s*\K[0-9]+' "$CONFIG_PATH" 2>/dev/null | head -1; }
mihomo_get_port() { [[ -f "$CONFIG_FILE" ]] && grep -oP '^\s*mixed-port:\s*\K[0-9]+' "$CONFIG_FILE" 2>/dev/null | head -1; }
mihomo_get_controller() { [[ -f "$CONFIG_FILE" ]] && grep -oP '^\s*external-controller:\s*\K\S+' "$CONFIG_FILE" 2>/dev/null | head -1; }
reality_get_port() {
    [[ -f "$REALITY_CONFIG" ]] || return
    local p
    p=$(grep -oP '"port"\s*:\s*\K[0-9]+(?=\s*,?\s*//\s*\*\*\*)' "$REALITY_CONFIG" 2>/dev/null | head -1)
    [[ -z "$p" ]] && p=$(sed -E 's#//.*$##' "$REALITY_CONFIG" 2>/dev/null | grep -oP '"port"\s*:\s*\K[0-9]+' | head -1)
    echo "$p"
}

# ---------- 通用: 放行本机防火墙端口 (供任意需要开端口的功能复用) ----------
# 用法: open_firewall <端口> [协议...]   协议默认 tcp; SS 等可传 "tcp udp"
# 覆盖 ufw / firewalld / iptables+ip6tables(双栈, -C 幂等, 尽力持久化); 仅 nftables 则提示手动
open_firewall() {
    local port="$1"; shift
    local protos=("$@"); [ ${#protos[@]} -eq 0 ] && protos=("tcp")
    local opened="" proto did=""
    if command -v ufw >/dev/null 2>&1; then
        for proto in "${protos[@]}"; do ufw allow "${port}/${proto}" >/dev/null 2>&1; done
        opened="ufw (v4+v6)"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        for proto in "${protos[@]}"; do firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1; done
        firewall-cmd --reload >/dev/null 2>&1
        opened="firewalld (v4+v6)"
    else
        for proto in "${protos[@]}"; do
            if command -v iptables >/dev/null 2>&1; then
                iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null \
                    || iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null
                did="iptables"
            fi
            if command -v ip6tables >/dev/null 2>&1; then
                ip6tables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null \
                    || ip6tables -I INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null
                did="iptables+ip6tables"
            fi
        done
        if [ -n "$did" ]; then
            if command -v netfilter-persistent >/dev/null 2>&1; then
                netfilter-persistent save >/dev/null 2>&1
            elif [ -d /etc/iptables ] && command -v iptables-save >/dev/null 2>&1; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null
                command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
            elif command -v service >/dev/null 2>&1; then
                service iptables save >/dev/null 2>&1
            fi
            opened="$did"
        fi
    fi

    local plist="${protos[*]}"
    if [ -n "$opened" ]; then
        echo -e "${GREEN}  ✓ 已放行本机防火墙: ${port} (${plist}) [${opened}]${NC}"
    elif command -v nft >/dev/null 2>&1; then
        echo -e "${YELLOW}  · 检测到 nftables 但无 ufw/firewalld: 未自动放行, 请手动放行 ${port} (${plist})${NC}"
    else
        echo -e "${YELLOW}  · 未检测到受支持的防火墙工具; 若有防火墙/云安全组请手动放行 ${port} (${plist})${NC}"
    fi
}

# --- 2. 状态面板 ---
check_status() {
    clear
    detect_os
    echo -e "${BLUE}================ 系统与 SSH 环境状态 ================${NC}"
    
    # 手动对齐冒号（中文占2个显示宽度）
    echo -e "操作系统            : ${GREEN_BOLD}$OS_NAME${NC}"
    echo -e "系统架构            : ${GREEN_BOLD}$OS_ARCH${NC}"
    
    # SELinux 状态（未安装/禁用显示红色）
    if [[ "$SELINUX_STATE" == "未安装/禁用" ]]; then
        echo -e "SELinux 状态        : ${RED_BOLD}$SELINUX_STATE${NC}"
    else
        echo -e "SELinux 状态        : ${GREEN_BOLD}$SELINUX_STATE${NC}"
    fi
    
    echo -e "系统时区            : ${GREEN_BOLD}$CURRENT_TIMEZONE${NC}"
    
    local current_locale=$(locale 2>/dev/null | grep "^LANG=" | cut -d= -f2 || echo "未知")
    if [[ "$current_locale" == "未知" ]]; then
        echo -e "当前 Locale         : ${RED_BOLD}$current_locale${NC}"
    else
        echo -e "当前 Locale         : ${GREEN_BOLD}$current_locale${NC}"
    fi
    
    # 检测 Root 登录状态
    local root_login=$(grep "^PermitRootLogin" $SSH_CONF | awk '{print $2}')
    [ -z "$root_login" ] && root_login="默认(prohibit-password)"
    
    # 检测密码验证状态（优先检查云平台配置）
    local pwd_auth=""
    local config_dir="/etc/ssh/sshd_config.d"
    
    # 首先检查云平台配置文件
    if [ -d "$config_dir" ]; then
        for conf_file in "60-cloudimg-settings.conf" "50-cloud-init.conf" "99-cloudimg-settings.conf"; do
            if [ -f "$config_dir/$conf_file" ]; then
                local cloud_pwd=$(grep "^PasswordAuthentication" "$config_dir/$conf_file" 2>/dev/null | awk '{print $2}')
                if [ -n "$cloud_pwd" ]; then
                    pwd_auth="$cloud_pwd"
                    break
                fi
            fi
        done
    fi
    
    # 如果云平台配置中没有，检查主配置文件
    if [ -z "$pwd_auth" ]; then
        pwd_auth=$(grep "^PasswordAuthentication" $SSH_CONF 2>/dev/null | awk '{print $2}')
    fi
    
    # 如果还是没找到，默认为yes
    [ -z "$pwd_auth" ] && pwd_auth="yes(默认)"
    
    # 检测端口
    local ports=$(grep "^Port " $SSH_CONF | awk '{print $2}' | xargs)
    [ -z "$ports" ] && ports="22(默认)"
    
    # 检测密钥文件
    local auth_file_status="不存在"
    local auth_file_color="${RED_BOLD}"
    if [ -f "$AUTH_KEYS" ]; then
        auth_file_status="已存在 ($(ls -lh $AUTH_KEYS | awk '{print $5}'))"
        auth_file_color="${GREEN_BOLD}"
    fi

    # 检测 SS 安装状态
    local ss_status="未安装"
    local ss_color="${RED_BOLD}"
    if [[ -f "$BINARY_PATH" && -f "$CONFIG_PATH" ]]; then
        if systemctl is-active ss >/dev/null 2>&1; then
            ss_status="已安装 + 运行中"
            ss_color="${GREEN_BOLD}"
        else
            ss_status="已安装 未运行"
            ss_color="${YELLOW}"
        fi
    fi

    # 检测 Mihomo 安装状态
    local mihomo_status="未安装"
    local mihomo_color="${RED_BOLD}"
    if [[ -f "$CORE_BIN" && -f "$CONFIG_FILE" ]]; then
        if systemctl is-active mihomo >/dev/null 2>&1; then
            mihomo_status="已安装 + 运行中"
            mihomo_color="${GREEN_BOLD}"
        else
            mihomo_status="已安装 未运行"
            mihomo_color="${YELLOW}"
        fi
    fi

    # 检测 Reality (VLESS) 安装状态
    local reality_status="未安装"
    local reality_color="${RED_BOLD}"
    if [[ -f "$REALITY_CONFIG" ]]; then
        if systemctl is-active xray >/dev/null 2>&1; then
            reality_status="已安装 + 运行中"
            reality_color="${GREEN_BOLD}"
        else
            reality_status="已安装 未运行"
            reality_color="${YELLOW}"
        fi
    fi

    # Root 登录（yes显示绿色，no显示红色）
    if [[ "$root_login" =~ ^(yes|YES)$ ]]; then
        echo -e "Root 登录           : ${GREEN_BOLD}$root_login${NC}"
    else
        echo -e "Root 登录           : ${RED_BOLD}$root_login${NC}"
    fi
    
    # 密码验证（no显示绿色更安全，yes显示红色）
    if [[ "$pwd_auth" =~ ^(no|NO)$ ]]; then
        echo -e "密码验证            : ${GREEN_BOLD}$pwd_auth${NC}"
    else
        echo -e "密码验证            : ${RED_BOLD}$pwd_auth${NC}"
    fi
    
    echo -e "SSH 端口            : ${GREEN_BOLD}$ports${NC}"
    echo -e "密钥文件状态        : ${auth_file_color}$auth_file_status${NC}"
    # 端口(仅在已安装时解析显示)
    local ss_ps="" mihomo_ps="" reality_ps="" _p
    if [[ "$ss_status" != "未安装" ]]; then _p=$(ss_get_port); [[ -n "$_p" ]] && ss_ps="  端口 ${_p}"; fi
    if [[ "$mihomo_status" != "未安装" ]]; then _p=$(mihomo_get_port); [[ -n "$_p" ]] && mihomo_ps="  端口 ${_p}"; fi
    if [[ "$reality_status" != "未安装" ]]; then _p=$(reality_get_port); [[ -n "$_p" ]] && reality_ps="  端口 ${_p}"; fi
    echo -e "SS 状态             : ${ss_color}$ss_status${NC}${CYAN}${ss_ps}${NC}"
    echo -e "Mihomo 状态         : ${mihomo_color}$mihomo_status${NC}${CYAN}${mihomo_ps}${NC}"
    echo -e "Reality 状态        : ${reality_color}$reality_status${NC}${CYAN}${reality_ps}${NC}"
    
    # BBR 状态显示
    if [[ "$BBR_STATUS" == "已启用" ]]; then
        echo -e "BBR 加速            : ${GREEN_BOLD}$BBR_STATUS${NC} (内核 ${KERNEL_VERSION})"
    else
        echo -e "BBR 加速            : ${RED_BOLD}$BBR_STATUS${NC} (内核 ${KERNEL_VERSION})"
    fi
    
    echo -e "${BLUE}=====================================================${NC}"
}

# --- 通用依赖安装器 (apt/yum), 供各模块共用 ---
install_package_if_missing() {
    local command_name="$1"
    local package_name="${2:-$1}"
    if _exists "$command_name"; then
        return 0
    fi
    echo "未检测到 $command_name，正在安装..."
    if _exists apt-get; then
        apt-get update
        apt-get install -y "$package_name"
    elif _exists yum; then
        yum install -y "$package_name"
    else
        echo "无法自动安装 $package_name，请手动安装后重试。"
        return 1
    fi
}

