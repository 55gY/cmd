#!/bin/bash
# modules/mihomo.sh — Mihomo 代理管理. 依赖 lib/common.sh

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

# Mihomo 状态检测面板 (统一样式)
mihomo_status_panel() {
    local local_ip controller mixed_port ctrl_port ctrl_url="未配置" proxy_url="未配置"
    local_ip=$(get_local_ip)
    if [ -f "$CONFIG_FILE" ]; then
        controller=$(mihomo_get_controller)
        mixed_port=$(mihomo_get_port)
        [ -n "$controller" ] && { ctrl_port="${controller##*:}"; ctrl_url="http://${local_ip}:${ctrl_port}/ui"; }
        [ -n "$mixed_port" ] && proxy_url="http://${local_ip}:${mixed_port}"
    fi
    panel_top "Mihomo 状态检测"
    if [ -f "$CORE_BIN" ]; then
        echo -e "程序 (Binary)    : ${GREEN_BOLD}已安装${NC}  ${CYAN}${CORE_BIN}${NC}"
    else
        echo -e "程序 (Binary)    : ${RED_BOLD}未安装${NC}"
    fi
    if [ -f "$CONFIG_FILE" ]; then
        echo -e "配置文件         : ${GREEN_BOLD}已存在${NC}"
    else
        echo -e "配置文件         : ${RED_BOLD}未生成${NC}"
    fi
    echo -e "服务状态         : $(svc_status_str mihomo)"
    echo -e "代理端口         : ${CYAN}${mixed_port:-未知}${NC}  $(port_listen_str "$mixed_port")"
    echo -e "控制面板         : ${CYAN}${ctrl_url}${NC}"
    echo -e "代理地址         : ${CYAN}${proxy_url}${NC}"
    panel_bot
}

mihomo_menu() {
    local choice
    while true; do
        init_log_dir
        clear
        mihomo_status_panel
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
