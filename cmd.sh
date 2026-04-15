#!/bin/bash

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
DEFAULT_CONFIG_CONTENT=$(cat <<'EOF'
proxy-providers:
  provider1:
    url: "订阅1"
    type: http
    interval: 1800
    health-check: {enable: true,url: "https://www.gstatic.com/generate_204",interval: 300}
    override:
      additional-prefix: "[provider1]"

  provider2:
    url: "订阅2"
    type: http
    interval: 1800
    health-check: {enable: true,url: "https://www.gstatic.com/generate_204",interval: 300}
    override:
      additional-prefix: "[provider2]"

proxies: 
  - name: "直连"
    type: direct
    udp: true

mixed-port: 7890
ipv6: true
allow-lan: true
unified-delay: false
tcp-concurrent: true
external-controller: 0.0.0.0:9090
secret: ""
external-ui: ui
external-ui-url: "https://ghfast.top/https://github.com/Zephyruso/zashboard/archive/refs/heads/gh-pages.zip"

find-process-mode: off
global-client-fingerprint: chrome

profile:
  store-selected: true
  store-fake-ip: true

sniffer:
  enable: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]
  skip-domain:
    - "Mijia Cloud"
    - "+.push.apple.com"

tun:
  enable: true
  stack: mixed
  dns-hijack:
    - "any:53"
    - "tcp://any:53"
  auto-route: true
  auto-redirect: true
  auto-detect-interface: true

dns:
  enable: true
  ipv6: true
  respect-rules: true
  enhanced-mode: fake-ip
  fake-ip-filter-mode: blacklist
  fake-ip-filter:
    - "*"
    - "+.lan"
    - "+.local"
    - "rule-set:cn_domain"
    - "rule-set:private_domain"
    - "+.apple.com"
    - "+.xn--ngstr-lra8j.com"
    - "+.services.googleapis.cn"
    
  nameserver:
    - https://120.53.53.53/dns-query
    - https://223.5.5.5/dns-query
  proxy-server-nameserver:
    - https://120.53.53.53/dns-query
    - https://223.5.5.5/dns-query
  nameserver-policy:
    "rule-set:cn_domain,private_domain":
      - https://120.53.53.53/dns-query
      - https://223.5.5.5/dns-query
    "rule-set:geolocation-!cn":
      - "https://dns.cloudflare.com/dns-query"
      - "https://dns.google/dns-query"

proxy-groups:

  - name: 默认
    type: select
    proxies: [自动选择,直连,香港,台湾,日本,新加坡,美国,其它地区,全部节点]

  - name: Google
    type: select
    proxies: [默认,香港,台湾,日本,新加坡,美国,其它地区,全部节点,自动选择,直连]

  - name: Telegram
    type: select
    proxies: [默认,香港,台湾,日本,新加坡,美国,其它地区,全部节点,自动选择,直连]

  - name: Twitter
    type: select
    proxies: [默认,香港,台湾,日本,新加坡,美国,其它地区,全部节点,自动选择,直连]

  - name: 哔哩哔哩
    type: select
    proxies: [默认,香港,台湾,日本,新加坡,美国,其它地区,全部节点,自动选择,直连]

  - name: 巴哈姆特
    type: select
    proxies: [默认,香港,台湾,日本,新加坡,美国,其它地区,全部节点,自动选择,直连]

  - name: YouTube
    type: select
    proxies: [默认,香港,台湾,日本,新加坡,美国,其它地区,全部节点,自动选择,直连]

  - name: NETFLIX
    type: select
    proxies: [默认,香港,台湾,日本,新加坡,美国,其它地区,全部节点,自动选择,直连]

  - name: Spotify
    type: select
    proxies:  [默认,香港,台湾,日本,新加坡,美国,其它地区,全部节点,自动选择,直连]

  - name: Github
    type: select
    proxies:  [默认,香港,台湾,日本,新加坡,美国,其它地区,全部节点,自动选择,直连]

  - name: 国内
    type: select
    proxies:  [直连,默认,香港,台湾,日本,新加坡,美国,其它地区,全部节点,自动选择]

  - name: 其他
    type: select
    proxies:  [默认,香港,台湾,日本,新加坡,美国,其它地区,全部节点,自动选择,直连]

  #分隔,下面是地区分组
  - name: 香港
    type: select
    include-all: true
    exclude-type: direct
    filter: "(?i)港|hk|hongkong|hong kong"

  - name: 台湾
    type: select
    include-all: true
    exclude-type: direct
    filter: "(?i)台|tw|taiwan"

  - name: 日本
    type: select
    include-all: true
    exclude-type: direct
    filter: "(?i)日|jp|japan"

  - name: 美国
    type: select
    include-all: true
    exclude-type: direct
    filter: "(?i)美|us|unitedstates|united states"

  - name: 新加坡
    type: select
    include-all: true
    exclude-type: direct
    filter: "(?i)(新|sg|singapore)"

  - name: 其它地区
    type: select
    include-all: true
    exclude-type: direct
    filter: "(?i)^(?!.*(?:🇭🇰|🇯🇵|🇺🇸|🇸🇬|🇰🇷|港|hk|hongkong|台|tw|taiwan|日|jp|japan|新|sg|singapore|美|us|unitedstates|韩|韩国|KR|kora)).*"

  - name: 全部节点
    type: select
    include-all: true
    exclude-type: direct

  - name: 自动选择
    type: url-test
    include-all: true
    exclude-type: direct
    tolerance: 10

rules:
  - RULE-SET,private_ip,直连,no-resolve
  - RULE-SET,github_domain,Github
  - RULE-SET,twitter_domain,Twitter
  - RULE-SET,youtube_domain,YouTube
  - RULE-SET,google_domain,Google
  - RULE-SET,telegram_domain,Telegram
  - RULE-SET,netflix_domain,NETFLIX
  - RULE-SET,bilibili_domain,哔哩哔哩
  - RULE-SET,bahamut_domain,巴哈姆特
  - RULE-SET,spotify_domain,Spotify
  - RULE-SET,cn_domain,国内
  - RULE-SET,geolocation-!cn,其他

  - RULE-SET,google_ip,Google
  - RULE-SET,netflix_ip,NETFLIX
  - RULE-SET,telegram_ip,Telegram
  - RULE-SET,twitter_ip,Twitter
  - RULE-SET,cn_ip,国内
  - MATCH,其他

rule-anchor:
  ip: &ip {type: http, interval: 1800, behavior: ipcidr, format: mrs}
  domain: &domain {type: http, interval: 1800, behavior: domain, format: mrs}
rule-providers:
  private_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/private.mrs"
  cn_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs"
  biliintl_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/biliintl.mrs"
  ehentai_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/ehentai.mrs"
  github_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/github.mrs"
  twitter_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/twitter.mrs"
  youtube_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/youtube.mrs"
  google_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google.mrs"
  telegram_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/telegram.mrs"
  netflix_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/netflix.mrs"
  bilibili_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/bilibili.mrs"
  bahamut_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/bahamut.mrs"
  spotify_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/spotify.mrs"
  pixiv_domain:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/pixiv.mrs"
  geolocation-!cn:
    <<: *domain
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/geolocation-!cn.mrs"

  private_ip:
    <<: *ip
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/private.mrs"
  cn_ip:
    <<: *ip
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs"
  google_ip:
    <<: *ip
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/google.mrs"
  netflix_ip:
    <<: *ip
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/netflix.mrs"
  twitter_ip:
    <<: *ip
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/twitter.mrs"
  telegram_ip:
    <<: *ip
    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/telegram.mrs"
EOF
)

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
    echo -e "SS 状态             : ${ss_color}$ss_status${NC}"
    echo -e "Mihomo 状态         : ${mihomo_color}$mihomo_status${NC}"
    
    # BBR 状态显示
    if [[ "$BBR_STATUS" == "已启用" ]]; then
        echo -e "BBR 加速            : ${GREEN_BOLD}$BBR_STATUS${NC} (内核 ${KERNEL_VERSION})"
    else
        echo -e "BBR 加速            : ${RED_BOLD}$BBR_STATUS${NC} (内核 ${KERNEL_VERSION})"
    fi
    
    echo -e "${BLUE}=====================================================${NC}"
}

# --- 3. SSH 配置辅助函数 ---
# 修改SSH配置项（支持模块化配置目录）
set_ssh_config() {
    local key="$1"
    local value="$2"
    local pattern="^#\\?${key}"
    
    # 转义 value 中的特殊字符（用于 sed）
    local escaped_value=$(echo "$value" | sed 's/[&/\\]/\\&/g')
    
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
                    sed -i "s/$pattern.*/${key} ${escaped_value}/" "$cloud_config"
                    echo -e "${GREEN}  ✓ 已更新 $conf_file 中的 $key${NC}"
                fi
            fi
        done
    fi
    
    # 同时修改主配置文件
    if grep -q "$pattern" "$SSH_CONF"; then
        sed -i "s/$pattern.*/${key} ${escaped_value}/" "$SSH_CONF"
    else
        echo "${key} ${value}" >> "$SSH_CONF"
    fi
    echo -e "${GREEN}  ✓ 已更新主配置文件中的 $key${NC}"
}

configure_ssh_socket_ports() {
    local mode="$1"
    local new_port="$2"
    local socket_unit="${SERVICE_NAME}.socket"
    local dropin_dir="/etc/systemd/system/${socket_unit}.d"
    local override_file="$dropin_dir/override.conf"
    local current_ports=""
    local final_ports=()
    local port

    if ! systemctl list-unit-files "$socket_unit" >/dev/null 2>&1; then
        return 0
    fi

    if ! systemctl is-enabled "$socket_unit" >/dev/null 2>&1 && ! systemctl is-active "$socket_unit" >/dev/null 2>&1; then
        return 0
    fi

    current_ports=$(systemctl show -p Listen "$socket_unit" 2>/dev/null | sed 's/^Listen=//')
    if [ -n "$current_ports" ]; then
        while IFS= read -r port; do
            port=$(echo "$port" | sed 's/.*://')
            if [[ "$port" =~ ^[0-9]+$ ]]; then
                final_ports+=("$port")
            fi
        while IFS= read -r port; do ...; done <<< "$(tr ' ' '\n' <<< "$current_ports")"
    fi

    if [[ "$mode" =~ ^[Aa]$ ]]; then
        if [ ${#final_ports[@]} -eq 0 ]; then
            final_ports=("22")
        fi
        if [[ ! " ${final_ports[*]} " =~ " ${new_port} " ]]; then
            final_ports+=("$new_port")
        fi
    else
        final_ports=("$new_port")
    fi

    mkdir -p "$dropin_dir"

    {
        echo "[Socket]"
        echo "ListenStream="
        for port in "${final_ports[@]}"; do
            echo "ListenStream=${port}"
        done
    } > "$override_file"

    systemctl daemon-reload
    echo -e "${GREEN}  ✓ 已更新 ${socket_unit} 的监听端口: ${final_ports[*]}${NC}"
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
    if [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        echo -e "${RED}端口号超出范围，请输入 1-65535 之间的值${NC}"
        return
    fi

    # 修改配置逻辑
    read -p "模式: [A]追加(保留22) | [R]替换(仅新端口): " p_mode
    if [[ "$p_mode" =~ ^[Aa]$ ]]; then
        sed -i 's/^#Port 22/Port 22/' $SSH_CONF
        grep -q "^Port $new_port" $SSH_CONF || sed -i "/^Port 22/a Port $new_port" $SSH_CONF
    else
        sed -i "s/^#\?Port.*/Port $new_port/" $SSH_CONF
    fi

    configure_ssh_socket_ports "$p_mode" "$new_port"

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

# PTY 最大数量（防止 SSH 连接被拒绝）
kernel.pty.max = 4096

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
    
    # 配置 SSH 连接保活和会话限制
    echo -e "${BLUE}配置 SSH 连接保活参数...${NC}"
    
    # 备份 SSH 配置
    if [ -f /etc/ssh/sshd_config ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)
    fi
    
    # 删除旧的配置（如果存在）
    sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config
    sed -i '/^ClientAliveCountMax/d' /etc/ssh/sshd_config
    sed -i '/^MaxSessions/d' /etc/ssh/sshd_config
    sed -i '/^MaxStartups/d' /etc/ssh/sshd_config
    
    # 添加新配置到文件末尾
    cat >> /etc/ssh/sshd_config <<-EOF

# SSH 连接保活配置（防止断线）- 添加于 $(date +%Y-%m-%d)
# 每 30 秒发一次心跳
ClientAliveInterval 30
# 如果连续 3 次没回应（即 90 秒），才彻底断开
ClientAliveCountMax 3
# 最大允许开启的会话数
MaxSessions 100
# 最大允许建立的连接数
MaxStartups 10:30:100
EOF
    
    echo -e "${GREEN}✓ 已配置 SSH 连接保活参数${NC}"
    
    # 应用配置
    sysctl -p >/dev/null 2>&1
    source /etc/profile 2>/dev/null || true
    
    # 重启 SSH 服务使配置生效
    echo -e "${BLUE}重启 SSH 服务使配置生效...${NC}"
    detect_os  # 确保 SERVICE_NAME 变量已设置
    systemctl restart $SERVICE_NAME 2>/dev/null || service $SERVICE_NAME restart 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ SSH 服务已重启${NC}"
    else
        echo -e "${YELLOW}⚠ SSH 服务重启可能失败，建议手动检查${NC}"
    fi
    
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

init_log_dir() {
    mkdir -p "$LOG_DIR"
    touch "$INSTALL_LOG"
    chmod 755 "$LOG_DIR"
    chmod 644 "$INSTALL_LOG"
}

log_message() {
    local message="$1"
    echo "$message" | tee -a "$INSTALL_LOG"
}

get_local_ip() {
    local ip_addr=""

    if _exists hostname; then
        ip_addr=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi

    if [ -z "$ip_addr" ] && _exists ip; then
        ip_addr=$(ip route get 1 2>/dev/null | awk '/src/ {for (i = 1; i <= NF; i++) if ($i == "src") {print $(i + 1); exit}}')
    fi

    if [ -z "$ip_addr" ]; then
        ip_addr="127.0.0.1"
    fi

    echo "$ip_addr"
}

get_config_value() {
    local key="$1"

    if [ ! -f "$CONFIG_FILE" ]; then
        return 1
    fi

    awk -F ': ' -v search_key="$key" '$1 == search_key {print $2; exit}' "$CONFIG_FILE" | tr -d '"'
}

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

ensure_mihomo_dependencies() {
    install_package_if_missing curl || return 1
    install_package_if_missing wget || return 1
    install_package_if_missing jq || return 1
    install_package_if_missing gzip || return 1
    install_package_if_missing tar || return 1
    install_package_if_missing bc || return 1
}

fetch_release_assets() {
    local api_url="$1"
    local version_type="$2"
    local response
    if ! response=$(curl -fsSL "$api_url"); then
        log_message "获取 $version_type 版本信息失败，请检查网络。"
        return 1
    fi
    echo "$response" | jq -r 'if type=="array" then
         .[] | .tag_name as $tag | .assets[] | select(.name | test("^mihomo-linux.*\\.gz$")) | [.name, $tag] | @tsv
       else
         .tag_name as $tag | .assets[] | select(.name | test("^mihomo-linux.*\\.gz$")) | [.name, $tag] | @tsv
       end'
}

detect_arch_pattern() {
    local machine_arch
    machine_arch=$(uname -m)
    case "$machine_arch" in
        x86_64|amd64)
            echo "amd64|x86_64"
            ;;
        aarch64|arm64)
            echo "arm64|aarch64"
            ;;
        armv7l|armv7|armhf)
            echo "armv7|armv7l|armhf"
            ;;
        armv6l|armv6)
            echo "armv6|armv6l"
            ;;
        i386|i686)
            echo "386|i386|i686"
            ;;
        *)
            echo ""
            ;;
    esac
}

select_release_asset_for_current_arch() {
    local versions="$1"
    local arch_pattern
    arch_pattern=$(detect_arch_pattern)
    if [ -z "$arch_pattern" ]; then
        log_message "未识别的系统架构：$(uname -m)"
        return 1
    fi
    echo "$versions" | awk -F $'\t' -v pattern="$arch_pattern" '$1 ~ pattern {print; exit}'
}

create_mihomo_service_file() {
    cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=mihomo Daemon, Another Clash Kernel.
After=network.target NetworkManager.service systemd-networkd.service iwd.service
[Service]
Type=simple
LimitNPROC=500
LimitNOFILE=100000
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_TIME CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_TIME CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE
Restart=always
ExecStartPre=/usr/bin/sleep 1s
ExecStart=/usr/local/bin/mihomo -d /etc/mihomo
ExecReload=/bin/kill -HUP $MAINPID
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable mihomo.service >/dev/null 2>&1 || true
}

install_downloaded_binary() {
    local archive_name="$1"
    local temp_dir="$2"
    local extracted_file
    local backup_bin="${CORE_BIN}.bak"

    if [ ! -f "$temp_dir/$archive_name" ]; then
        log_message "下载文件不存在：$archive_name"
        return 1
    fi

    log_message "正在解压 $archive_name"
    gunzip -f "$temp_dir/$archive_name" || return 1
    extracted_file="${archive_name%.gz}"

    if [ -f "$CORE_BIN" ]; then
        mv "$CORE_BIN" "$backup_bin" || return 1
    fi

    if ! mv "$temp_dir/$extracted_file" "$CORE_BIN"; then
        if [ -f "$backup_bin" ]; then
            mv "$backup_bin" "$CORE_BIN" || true
        fi
        return 1
    fi

    rm -f "$backup_bin"
    chmod 755 "$CORE_BIN" || return 1
    mkdir -p "$CONFIG_DIR"
    log_message "mihomo 已安装到 $CORE_BIN"
    return 0
}

prepare_upgrade_if_needed() {
    local answer
    local service_running=0

    if [ ! -f "$CORE_BIN" ]; then
        return 0
    fi

    if _exists systemctl && systemctl is-active --quiet mihomo; then
        service_running=1
    fi

    if [ "$service_running" -eq 1 ]; then
        printf "${YELLOW}检测到 Mihomo 已安装，且服务正在运行。是否覆盖升级并保留现有配置？(y/n):${NC} "
    else
        printf "${YELLOW}检测到 Mihomo 已安装。是否覆盖升级并保留现有配置？(y/n):${NC} "
    fi
    read -r answer

    if [ "$answer" != "y" ]; then
        echo "已取消覆盖安装。"
        return 1
    fi

    if [ "$service_running" -eq 1 ]; then
        log_message "检测到 mihomo 服务正在运行，先停止服务再覆盖核心"
        if ! systemctl stop mihomo; then
            echo "停止 mihomo 服务失败，请手动检查后重试。"
            return 1
        fi
    fi

    return 0
}

install_selected_version() {
    local api_url="$1"
    local version_type="$2"
    local download_base="$3"
    local versions
    local selected
    local file_name
    local tag
    local temp_dir
    local download_url
    local http_code

    versions=$(fetch_release_assets "$api_url" "$version_type") || return 1
    if [ -z "$versions" ]; then
        echo "未找到可安装的 $version_type 版本。"
        return 1
    fi

    selected=$(select_release_asset_for_current_arch "$versions")
    if [ -z "$selected" ]; then
        echo "未找到适配当前系统架构 $(uname -m) 的 $version_type 安装包。"
        return 1
    fi

    file_name=$(echo "$selected" | awk -F $'\t' '{print $1}')
    tag=$(echo "$selected" | awk -F $'\t' '{print $2}')
    temp_dir=$(mktemp -d)
    download_url="$download_base/$tag/$file_name"
    log_message "自动匹配架构 $(uname -m)，选择安装包：$file_name"
    log_message "正在下载：$download_url"

    http_code=$(curl -L -s -w "%{http_code}" "$download_url" -o "$temp_dir/$file_name")
    if [ "$http_code" != "200" ]; then
        rm -rf "$temp_dir"
        echo "下载失败，HTTP 状态码：$http_code"
        return 1
    fi

    if ! install_downloaded_binary "$file_name" "$temp_dir"; then
        rm -rf "$temp_dir"
        echo "安装失败。"
        return 1
    fi

    rm -rf "$temp_dir"
    return 0
}

apply_default_config() {
    local answer
    mkdir -p "$CONFIG_DIR"
    if [ -z "$DEFAULT_CONFIG_CONTENT" ]; then
        echo "内置基础模板为空，无法写入。"
        return 1
    fi
    if [ -f "$CONFIG_FILE" ]; then
        printf "${RED}配置文件已存在，是否覆盖？(y/n):${NC} "
        read -r answer
        if [ "$answer" != "y" ]; then
            echo "取消覆盖。"
            return 1
        fi
    fi
    printf "%s" "$DEFAULT_CONFIG_CONTENT" > "$CONFIG_FILE" || return 1
    chmod 644 "$CONFIG_FILE"
    log_message "内置基础模板已写入 $CONFIG_FILE"
}

update_subscription_addresses() {
    local sub1
    local sub2
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "配置文件不存在，请先生成或导入配置。"
        return 1
    fi
    read -r -p "请输入订阅地址1（留空跳过）: " sub1
    if [ -n "$sub1" ]; then
        sed -i "s|url: \"订阅1\"|url: \"$sub1\"|" "$CONFIG_FILE"
        log_message "订阅地址1已更新"
    fi
    read -r -p "请输入订阅地址2（留空跳过）: " sub2
    if [ -n "$sub2" ]; then
        sed -i "s|url: \"订阅2\"|url: \"$sub2\"|" "$CONFIG_FILE"
        log_message "订阅地址2已更新"
    fi
}

restart_network_service() {
    local restart_output=""
    if systemctl is-active --quiet NetworkManager; then
        restart_output=$(systemctl restart NetworkManager 2>&1)
    elif systemctl is-active --quiet systemd-networkd; then
        restart_output=$(systemctl restart systemd-networkd 2>&1)
    elif systemctl is-active --quiet networking; then
        restart_output=$(systemctl restart networking 2>&1)
    elif _exists netplan; then
        restart_output=$(netplan apply 2>&1)
    else
        echo "No known network management service found"
        return 1
    fi
    [ -n "$restart_output" ] && log_message "$restart_output"
    echo "Network service restarted successfully"
}

first_run_mihomo() {
    local service_status
    local restart_output

    if [ ! -x "$CORE_BIN" ]; then
        echo "未检测到 mihomo 核心，请先执行安装。"
        return 1
    fi
    if [ ! -f "$CONFIG_FILE" ]; then
        echo "配置文件不存在，无法首次运行。"
        return 1
    fi

    echo "正在初始/重启..."
    create_mihomo_service_file
    systemctl daemon-reload
    systemctl enable mihomo >/dev/null 2>&1 || true

    if ! systemctl start mihomo; then
        echo "mihomo 启动失败，请检查 systemctl status mihomo。"
        return 1
    fi

    service_status=$(systemctl status mihomo 2>&1)
    echo "$service_status"
    if echo "$service_status" | grep -q "Active: failed"; then
        return 1
    fi

    sed -i '/net.ipv4.ip_forward/s/^#//;/net.ipv6.conf.all.forwarding/s/^#//' /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1 || true
    restart_output=$(restart_network_service 2>&1) || true
    log_message "$restart_output"

    if echo "$restart_output" | grep -q "No known network management service found"; then
        echo "未检测到有效的服务，请检查日志或重启系统。"
        return 1
    fi

    if systemctl is-active --quiet mihomo; then
        log_message "mihomo 首次运行成功"
        echo "mihomo 已成功启动。"
        return 0
    fi

    echo "mihomo 未成功进入运行状态，请检查 systemctl status mihomo。"
    return 1
}

one_click_install() {
    echo "开始执行一键安装..."
    init_log_dir
    ensure_mihomo_dependencies || return 1

    if ! prepare_upgrade_if_needed; then
        return 1
    fi

    if ! install_selected_version \
        "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest" \
        "发行" \
        "https://ghfast.top/https://github.com/MetaCubeX/mihomo/releases/download"; then
        echo "一键安装失败：核心安装未完成。"
        return 1
    fi

    if [ ! -f "$CONFIG_FILE" ]; then
        apply_default_config || return 1
    else
        log_message "检测到现有配置文件，保留原配置不覆盖"
    fi

    update_subscription_addresses || true
    first_run_mihomo
}

run_latency_test() {
    local num_tests=5
    local connect_timeout=10
    local log_file="$PWD/latency_log.txt"
    local predefined_targets=("www.google.com" "www.youtube.com" "www.cloudflare.com" "www.github.com" "www.baidu.com")
    local results=()
    local target_names=()
    local target
    local result

    run_single_test() {
        local test_target="$1"
        local total_duration_ms=0
        local min_time_ms=999
        local max_time_ms=0
        local successful_runs=0
        local response
        local connect_time_s
        local tls_time_s
        local run_time_s
        local connect_time_ms
        local tls_time_ms
        local run_time_ms
        local avg_time_ms
        local i

        case "$test_target" in
            http://*|https://*) ;;
            *) test_target="https://$test_target" ;;
        esac

        echo "================================================"
        echo "正在测试: $test_target"
        echo "================================================"

        for i in $(seq 1 "$num_tests"); do
            response=$(curl -s -H "Cache-Control: no-cache" -H "Pragma: no-cache" --connect-timeout "$connect_timeout" -o /dev/null -w "%{time_connect},%{time_pretransfer},%{time_total}" "${test_target}?_t=$(date +%s%N)")
            if [ $? -ne 0 ] || [ -z "$response" ]; then
                echo "第 $i/$num_tests 次：测试失败"
                continue
            fi

            successful_runs=$((successful_runs + 1))
            IFS=',' read -r connect_time_s tls_time_s run_time_s <<< "$response"
            connect_time_ms=$(awk -v time="$connect_time_s" 'BEGIN { printf "%.0f", time * 100 }')
            tls_time_ms=$(awk -v time="$tls_time_s" 'BEGIN { printf "%.0f", time * 100 }')
            run_time_ms=$(awk -v time="$run_time_s" 'BEGIN { printf "%.0f", time * 100 }')

            echo "第 $i/$num_tests 次：总延迟 = $run_time_ms ms (连接: $connect_time_ms ms, TLS: $tls_time_ms ms)"
            echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ"),$test_target,$i,$connect_time_s,$tls_time_s,$run_time_s" >> "$log_file"
            total_duration_ms=$((total_duration_ms + run_time_ms))
            [ "$run_time_ms" -lt "$min_time_ms" ] && min_time_ms=$run_time_ms
            [ "$run_time_ms" -gt "$max_time_ms" ] && max_time_ms=$run_time_ms
        done

        if [ "$successful_runs" -gt 0 ]; then
            avg_time_ms=$(awk -v total="$total_duration_ms" -v runs="$successful_runs" 'BEGIN { printf "%.2f", total / runs }')
            echo "最快: ${min_time_ms} ms"
            echo "最慢: ${max_time_ms} ms"
            echo "平均: ${avg_time_ms} ms"
            echo "$avg_time_ms"
        else
            echo "所有测试均失败。"
            echo "0"
        fi
    }

    show_batch_results() {
        local rank=1
        local color
        local sorted_lines
        local time
        local name
        local i

        echo ""
        echo "批量测试结果汇总"
        echo "--------------------------------"
        printf "%-20s %-15s %-10s\n" "目标域名" "平均延迟(ms)" "排名"
        echo "--------------------------------"

        sorted_lines=$(
            for i in "${!target_names[@]}"; do
                printf "%s\t%s\n" "${results[$i]}" "${target_names[$i]}"
            done | sort -n
        )

        while IFS=$'\t' read -r time name; do
            [ -z "$time" ] && continue

            if (( $(echo "$time < 200" | bc -l) )); then
                color="$GREEN"
            elif (( $(echo "$time < 500" | bc -l) )); then
                color="$YELLOW"
            else
                color="$RED"
            fi

            printf "%-20s ${color}%-15s${NC} %-10s\n" "$name" "$time" "$rank"
            rank=$((rank + 1))
        done <<< "$sorted_lines"

        echo "--------------------------------"
        echo "延迟越低表示连接速度越快"
    }

    [ ! -f "$log_file" ] && echo "Timestamp,Target,Run,Connect_Time_s,TLS_Time_s,Total_Time_s" > "$log_file"

    clear
    echo "================"
    echo "   外网真实延迟批量测试"
    echo "================"

    for target in "${predefined_targets[@]}"; do
        echo ""
        echo "开始测试目标: $target"
        result=$(run_single_test "$target" | tail -n 1)
        if [[ "$result" =~ ^[0-9]+([.][0-9]+)?$ ]] && (( $(echo "$result > 0" | bc -l) )); then
            results+=("$result")
            target_names+=("$target")
        fi
    done

    if [ ${#results[@]} -gt 0 ]; then
        show_batch_results
    else
        echo "没有有效的测试结果可显示。"
    fi
}

uninstall_mihomo() {
    local confirm
    echo "即将卸载 Mihomo 及相关配置。"
    read -r -p "确认继续？(y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "已取消卸载。"
        return 0
    fi

    if _exists systemctl; then
        systemctl stop mihomo >/dev/null 2>&1 || true
        systemctl disable mihomo >/dev/null 2>&1 || true
    fi
    rm -f "$CORE_BIN"
    rm -f "$SERVICE_FILE"
    rm -rf "$CONFIG_DIR"
    if _exists systemctl; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    echo "卸载完成。"
}

mihomo_menu() {
    local service_status="未安装"
    local_ip
    local controller_value=""
    local mixed_port=""
    local controller_port="9090"
    local controller_url="未配置"
    local proxy_url="未配置"
    local controller_color="$RED_BOLD"
    local proxy_color="$RED_BOLD"
    local binary_path_color="$RED_BOLD"
    local config_path_color="$RED_BOLD"
    local service_color="$RED_BOLD"
    local choice

    while true; do
        init_log_dir
        local_ip=$(get_local_ip)
        service_status="未安装"
        controller_value=""
        mixed_port=""
        controller_port="9090"
        controller_url="未配置"
        proxy_url="未配置"
        controller_color="$RED_BOLD"
        proxy_color="$RED_BOLD"
        binary_path_color="$RED_BOLD"
        config_path_color="$RED_BOLD"
        service_color="$RED_BOLD"

        if [ -f "$CONFIG_FILE" ]; then
            controller_value=$(get_config_value "external-controller")
            mixed_port=$(get_config_value "mixed-port")
            config_path_color="$GREEN_BOLD"

            if [ -n "$controller_value" ]; then
                controller_port="${controller_value##*:}"
                controller_url="http://${local_ip}:${controller_port}/ui"
                controller_color="$GREEN_BOLD"
            fi

            if [ -n "$mixed_port" ]; then
                proxy_url="http://${local_ip}:${mixed_port}"
                proxy_color="$GREEN_BOLD"
            fi
        fi

        if [ -f "$CORE_BIN" ]; then
            service_status="未运行"
            binary_path_color="$GREEN_BOLD"
            if _exists systemctl && systemctl is-active --quiet mihomo; then
                service_status="运行中"
                service_color="$GREEN_BOLD"
            elif _exists systemctl && systemctl list-unit-files | grep -q '^mihomo\.service'; then
                service_status="已停止"
                service_color="$YELLOW"
            fi
        fi

        clear
        echo -e "${BLUE}=================================================${NC}"
        echo -e "${BLUE}                 Mihomo 管理菜单                ${NC}"
        echo -e "${BLUE}=================================================${NC}"
        echo -e "控制面板地址        : ${BOLD}${controller_color}${controller_url}${NC}"
        echo -e "代理端口地址        : ${BOLD}${proxy_color}${proxy_url}${NC}"
        if [ -f "$CORE_BIN" ]; then
            echo -e "Mihomo程序路径      : ${BOLD}${binary_path_color}${CORE_BIN}${NC}"
        else
            echo -e "Mihomo程序路径      : ${BOLD}${binary_path_color}未安装${NC}"
        fi
        if [ -f "$CONFIG_FILE" ]; then
            echo -e "配置文件路径        : ${BOLD}${config_path_color}${CONFIG_FILE}${NC}"
        else
            echo -e "配置文件路径        : ${BOLD}${config_path_color}未生成${NC}"
        fi
        echo -e "服务状态            : ${BOLD}${service_color}${service_status}${NC}"
        echo -e "${BLUE}=================================================${NC}"
        echo "1. 一键安装"
        echo "2. 外网真实延迟测试"
        echo "3. 修改订阅"
        echo "4. 卸载"
        echo "0. 返回主菜单"
        read -r -p "请输入选项: " choice

        case "$choice" in
           1)
                one_click_install
                read -r -p "按回车返回 Mihomo 菜单..." _
                ;;
           2)
                ensure_mihomo_dependencies || true
                run_latency_test
                read -r -p "按回车返回 Mihomo 菜单..." _
                ;;
           3)
                update_subscription_addresses
                read -r -p "按回车返回 Mihomo 菜单..." _
                ;;
           4)
                uninstall_mihomo
                read -r -p "按回车返回 Mihomo 菜单..." _
                ;;
           0)
                break
                ;;
            *)
                echo "无效选项，请重新输入。"
                sleep 1
                ;;
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
    echo "2. 启用 BBR 网络优化"
    echo "3. 一键启用 Root 密钥登录"
    echo "4. 修改或新增 SSH 端口"
    echo "5. 修改系统时区为 Asia/Shanghai"
    echo "6. 安装中文字体和 Locale"
    echo "7. Mihomo 管理"
    echo "0. 退出"
    read -p "选择操作: " opt
    case $opt in
        1) ss_menu ;;
        2) enable_bbr; read -n 1 -p "按任意键继续..." ;;
        3) enable_key_login; read -n 1 -p "按任意键继续..." ;;
        4) change_port; read -n 1 -p "按任意键继续..." ;;
        5) change_timezone; read -n 1 -p "按任意键继续..." ;;
        6) install_chinese_support; read -n 1 -p "按任意键继续..." ;;
       7) mihomo_menu ;;
        0) exit 0 ;;
        *) echo "无效选项" ;;
    esac
done