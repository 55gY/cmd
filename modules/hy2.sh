#!/bin/bash
# modules/hy2.sh — Hysteria2 (Hy2) 管理. 依赖 lib/common.sh
# 由 crazypeace/hy2 的极简核心重写并按本项目规范重构而来:
#   官方 get.hy2.sh 装核心 + 自签证书 + 写 /etc/hysteria/config.yaml。
# Phase 1: 自签证书(默认)。Phase 2: 内置 ACME 真域名证书 + 伪装站。
# Phase 3: Salamander 混淆 + 协议嗅探 + 端口跳跃(原生 listen 段)。
# 端口/密码/证书域名默认随机或默认值, 每次重装为全新节点(与 Reality 同约定)。

# 复用 Reality 原脚本的小写调色命名, 映射到 common.sh 的配色
red="$RED"; green="$GREEN"; yellow="$YELLOW"; magenta="$PURPLE"; cyan="$CYAN"; none="$NC"

HY2_DEFAULT_PORT=2096
HY2_DEFAULT_DOMAIN="learn.microsoft.com"
HY2_DEFAULT_MASQ="https://news.ycombinator.com/"
HY2_DEFAULT_HOP_FIRST=20000
HY2_DEFAULT_HOP_LAST=50000
HY2_HOP_MIN_VERSION="2.8.0"
HY2_SERVICE="hysteria-server"
HY2_INFO="${HOME}/_hy2_url_"

# 探测公网 IP -> 设置 _hy2_ipv4 / _hy2_ipv6 (与 Reality 同法: 按网口问 Cloudflare trace)
_hy2_detect_ip() {
    _hy2_ipv4=""; _hy2_ipv6=""
    local InFaces i p4 p6
    InFaces=($(ls /sys/class/net/ 2>/dev/null | grep -E '^(eth|ens|eno|esp|enp|venet|vif)'))
    for i in "${InFaces[@]}"; do
        p4=$(curl -4s --interface "$i" -m 2 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -oP "ip=\K.*$")
        p6=$(curl -6s --interface "$i" -m 2 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -oP "ip=\K.*$")
        [[ -n "$p4" ]] && _hy2_ipv4="$p4"
        [[ -n "$p6" ]] && _hy2_ipv6="$p6"
    done
}

# 解析现有 config.yaml -> _hy2_* 状态变量; 设置 _hy2_cfg_valid (1=有效)
# 分段感知 awk 回读全部块: 监听端口/跳跃段、证书类型(自签 tls / 内置 acme)、
# 域名/邮箱/ACME 类型/DNS token、伪装 URL、obfs 密码、sniff 开关。
# 自签模式的域名不在配置里, 从证书文件名取 (与 Phase 1 同口径)。
_hy2_parse_config() {
    _hy2_port=""; _hy2_password=""; _hy2_cert_type="selfsigned"; _hy2_domain=""; _hy2_email=""
    _hy2_acme_type="http"; _hy2_dns_name=""; _hy2_dns_token=""; _hy2_cert=""; _hy2_key=""; _hy2_pin=""
    _hy2_masq_url=""; _hy2_obfs_pw=""; _hy2_sniff=0; _hy2_hop=""
    _hy2_cfg_valid=0
    [[ -f "$HY2_CONFIG" ]] || return 1
    local _k _v
    while IFS="$(printf '\t')" read -r _k _v; do
        case "$_k" in
            port) _hy2_port="$_v" ;;
            hop) _hy2_hop="$_v" ;;
            cert_type) _hy2_cert_type="$_v" ;;
            domain) _hy2_domain="$_v" ;;
            email) _hy2_email="$_v" ;;
            acme_type) _hy2_acme_type="$_v" ;;
            dns_name) _hy2_dns_name="$_v" ;;
            dns_token) _hy2_dns_token="$_v" ;;
            cert) _hy2_cert="$_v" ;;
            key) _hy2_key="$_v" ;;
            password) _hy2_password="$_v" ;;
            masq) _hy2_masq_url="$_v" ;;
            obfs) _hy2_obfs_pw="$_v" ;;
            sniff) [[ "$_v" == "true" ]] && _hy2_sniff=1 || _hy2_sniff=0 ;;
        esac
    done < <(awk '
        function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
        function val(t) { return trim(substr(t, index(t, ":") + 1)) }
        {
            line = $0
            if (line ~ /^[^ \t#]/) {
                split(line, a, ":"); section = trim(a[1])
                if (section == "listen") {
                    v = val(line); sub(/^:/, "", v)
                    if (v ~ /-/) { split(v, r, "-"); print "port\t" r[1]; print "hop\t" v }
                    else print "port\t" v
                }
                next
            }
            t = trim(line)
            if (t == "" || t ~ /^#/) next
            if (section == "acme") {
                if (!acme_seen) { print "cert_type\tacme"; acme_seen = 1 }
                if (t ~ /^- /) { sub(/^- /, "", t); print "domain\t" t }
                else if (t ~ /^email:/) print "email\t" val(t)
                else if (t ~ /^type:/) print "acme_type\t" val(t)
                else if (t ~ /^name:/) print "dns_name\t" val(t)
                else if (t ~ /^cloudflare_api_token:/) print "dns_token\t" val(t)
                else if (t ~ /^duckdns_api_token:/) print "dns_token\t" val(t)
            } else if (section == "tls") {
                if (t ~ /^cert:/) print "cert\t" val(t)
                else if (t ~ /^key:/) print "key\t" val(t)
            } else if (section == "auth") {
                if (t ~ /^password:/) print "password\t" val(t)
            } else if (section == "masquerade") {
                if (t ~ /^url:/) print "masq\t" val(t)
            } else if (section == "obfs") {
                if (t ~ /^password:/) print "obfs\t" val(t)
            } else if (section == "sniff") {
                if (t ~ /^enable:/) print "sniff\t" val(t)
            }
        }
    ' "$HY2_CONFIG")
    if [[ "$_hy2_cert_type" != "acme" && -n "$_hy2_cert" ]]; then
        _hy2_domain=$(basename "$_hy2_cert" .crt)
        if [[ -f "$_hy2_cert" ]]; then
            _hy2_pin=$(openssl x509 -in "$_hy2_cert" -outform DER 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}')
        fi
    fi
    if [[ -n "$_hy2_port" && -n "$_hy2_password" ]]; then
        if [[ "$_hy2_cert_type" == "acme" ]]; then
            [[ -n "$_hy2_domain" && -n "$_hy2_email" ]] && _hy2_cfg_valid=1
        else
            [[ -n "$_hy2_cert" && -n "$_hy2_key" && -f "$_hy2_cert" && -f "$_hy2_key" ]] && _hy2_cfg_valid=1
        fi
    fi
    return 0
}

# 服务是否在运行 (systemctl 优先, 无 systemctl 时看 UDP 绑定)
_hy2_service_active() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet "$HY2_SERVICE" 2>/dev/null
    else
        ss -lun "sport = :${_hy2_port}" 2>/dev/null | grep -q ":${_hy2_port}[^0-9]"
    fi
}

# 重启服务 (systemctl 优先, 回退 service)
_hy2_restart_service() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart "$HY2_SERVICE" 2>/dev/null || service "$HY2_SERVICE" restart 2>/dev/null
    else
        service "$HY2_SERVICE" restart 2>/dev/null
    fi
}

# 分项检测面板 (统一样式): Hysteria 程序 / 配置 / 配置有效性 / 服务 / 端口监听(UDP)
# + 证书类型 / 伪装站 / 混淆 / 嗅探 / 端口跳跃
hy2_status_panel() {
    local hyver=""
    [[ -x "$HY2_BIN" ]] && hyver=$("$HY2_BIN" version 2>/dev/null | grep '^Version' | grep -o 'v[.0-9]*' | head -1)
    _hy2_parse_config
    local port; port=$(hy2_get_port)
    panel_top "Hysteria2 环境检测"
    if [[ -x "$HY2_BIN" ]]; then
        echo -e "Hysteria 程序     : ${GREEN_BOLD}已安装${NC}${CYAN}${hyver:+ (${hyver})}${NC}"
    else
        echo -e "Hysteria 程序     : ${RED_BOLD}未安装${NC}"
    fi
    if [[ -f "$HY2_CONFIG" ]]; then
        echo -e "配置文件         : ${GREEN_BOLD}已存在${NC}"
        if [[ $_hy2_cfg_valid -eq 1 ]]; then
            echo -e "配置解析         : ${GREEN_BOLD}有效的 Hy2 配置${NC}"
        else
            echo -e "配置解析         : ${RED_BOLD}无法解析为 Hy2 配置${NC}"
        fi
    else
        echo -e "配置文件         : ${RED_BOLD}不存在${NC}"
    fi
    echo -e "服务状态         : $(svc_status_str "$HY2_SERVICE")"
    echo -e "开机自启         : ${CYAN}$(systemctl is-enabled "$HY2_SERVICE" 2>/dev/null || echo unknown)${NC}"
    echo -e "监听端口(UDP)    : ${CYAN}${port:-未知}${NC}  $(port_listen_udp_str "$port")"
    local cert_desc="自签"
    [[ "$_hy2_cert_type" == "acme" ]] && cert_desc="ACME (${_hy2_acme_type:-http})"
    echo -e "证书类型         : ${CYAN}${cert_desc}${NC}"
    echo -e "伪装站           : ${CYAN}${_hy2_masq_url:-未启用}${NC}"
    if [[ -n "$_hy2_obfs_pw" ]]; then
        echo -e "混淆             : ${CYAN}Salamander 已启用${NC}"
    else
        echo -e "混淆             : 未启用"
    fi
    if [[ "$_hy2_sniff" == "1" ]]; then
        echo -e "协议嗅探         : ${CYAN}已启用${NC}"
    else
        echo -e "协议嗅探         : 未启用"
    fi
    echo -e "端口跳跃         : ${CYAN}${_hy2_hop:-未启用}${NC}"
    panel_bot
}

# 查看现有节点配置 + 分享链接. 参数1: true=同时输出二维码 (默认 false)
# 链接按证书类型分支: ACME 用域名 + sni(无 insecure/pin); 自签用 IP + insecure=1 + pin。
# 有混淆加 &obfs=salamander&obfs-password=; 有跳跃加 &mport=首-尾, 地址端口取段首。
hy2_show_config() {
    local show_qr="${1:-false}"
    _hy2_parse_config
    if [[ $_hy2_cfg_valid -ne 1 ]]; then
        echo -e "${RED}未检测到有效的 Hysteria2 配置。${NC}"
        return 1
    fi
    _hy2_detect_ip
    local ip="" netstack="" disp_ip
    if [[ -n "$_hy2_ipv4" ]]; then ip="$_hy2_ipv4"; netstack=4
    elif [[ -n "$_hy2_ipv6" ]]; then ip="$_hy2_ipv6"; netstack=6; fi
    disp_ip="$ip"; [[ "$netstack" == "6" ]] && disp_ip="[$ip]"

    echo -e "${BLUE}---------- Hysteria2 节点配置 ----------${NC}"
    if [[ "$_hy2_cert_type" == "acme" ]]; then
        echo -e "$yellow 域名 (Domain) = ${cyan}${_hy2_domain}$none"
        echo -e "$yellow 证书 (TLS) = ${cyan}ACME 真证书 (${_hy2_acme_type})${none}"
    else
        echo -e "$yellow 地址 (Address) = ${cyan}${ip:-获取失败}$none"
        echo -e "$yellow 证书 (TLS) = ${cyan}自签证书${none}"
    fi
    echo -e "$yellow 端口 (Port) = ${cyan}${_hy2_port}$none"
    [[ -n "$_hy2_hop" ]] && echo -e "$yellow 端口跳跃 (Hop) = ${cyan}${_hy2_hop}${none}"
    echo -e "$yellow 密码 (Password) = ${cyan}${_hy2_password}$none"
    echo -e "$yellow 传输层安全 (TLS) = ${cyan}tls${none}"
    echo -e "$yellow 应用层协议协商 (Alpn) = ${cyan}h3${none}"
    if [[ "$_hy2_cert_type" == "acme" ]]; then
        echo -e "$yellow 证书域名 (SNI) = ${cyan}${_hy2_domain}$none"
    else
        echo -e "$yellow 跳过证书验证 (allowInsecure) = ${cyan}true${none}"
        echo -e "$yellow 证书域名 (SNI) = ${cyan}${_hy2_domain}$none"
        echo -e "$yellow 证书指纹 (pinSHA256) = ${cyan}${_hy2_pin}$none"
    fi
    [[ -n "$_hy2_masq_url" ]] && echo -e "$yellow 伪装站 (Masquerade) = ${cyan}${_hy2_masq_url}$none"
    [[ -n "$_hy2_obfs_pw" ]] && echo -e "$yellow 混淆 (Obfs) = ${cyan}salamander${none}"
    [[ "$_hy2_sniff" == "1" ]] && echo -e "$yellow 协议嗅探 (Sniff) = ${cyan}已启用${none}"
    if [[ "$_hy2_cert_type" == "acme" ]]; then
        echo -e "${YELLOW}ACME 真证书: 客户端不用开 allowInsecure, 用域名 + SNI 连接; 云服务器另需在安全组放行 UDP ${_hy2_port}。${NC}"
    else
        echo -e "${YELLOW}自签证书: 客户端须开 allowInsecure 或校验 pinSHA256; 云服务器另需在安全组放行 UDP ${_hy2_port}。${NC}"
    fi
    if [[ -n "$_hy2_hop" ]]; then
        echo -e "${YELLOW}端口跳跃: 安全组另需放行 UDP ${_hy2_hop} 整段。${NC}"
    fi
    if [[ "$_hy2_cert_type" == "acme" && "$_hy2_acme_type" == "http" ]]; then
        echo -e "${YELLOW}ACME 续期: 须保持 TCP 80 放行 (本机 + 安全组)。${NC}"
    fi
    if [[ -z "$ip" && "$_hy2_cert_type" != "acme" ]]; then
        echo -e "${RED}未获取到公网 IP, 无法生成分享链接。${NC}"
        return 1
    fi
    local host="$disp_ip" frag="$ip"
    if [[ "$_hy2_cert_type" == "acme" ]]; then host="$_hy2_domain"; frag="$_hy2_domain"; fi
    local query="alpn=h3"
    if [[ "$_hy2_cert_type" == "acme" ]]; then
        query="${query}&sni=${_hy2_domain}"
    else
        query="${query}&insecure=1&pinSHA256=${_hy2_pin}"
    fi
    [[ -n "$_hy2_obfs_pw" ]] && query="${query}&obfs=salamander&obfs-password=${_hy2_obfs_pw}"
    [[ -n "$_hy2_hop" ]] && query="${query}&mport=${_hy2_hop}"
    local url="hysteria2://${_hy2_password}@${host}:${_hy2_port}?${query}#HY2_${frag}"
    echo -e "$green 分享链接 (Share Link): $none"
    echo -e "${cyan}${url}${none}"
    echo "$url" > "$HY2_INFO" 2>/dev/null
    if [[ "$show_qr" == "true" ]]; then
        if command -v qrencode >/dev/null 2>&1; then
            echo
            qrencode -t ANSIUTF8 "$url"
        else
            echo -e "${YELLOW}未安装 qrencode, 跳过二维码。${NC}"
        fi
    fi
}

# 依赖
_hy2_deps() {
    install_package_if_missing curl >/dev/null 2>&1 || return 1
    install_package_if_missing wget >/dev/null 2>&1 || return 1
    install_package_if_missing openssl >/dev/null 2>&1 || return 1
    install_package_if_missing qrencode >/dev/null 2>&1 || true
}

# 安装 / 更新 Hysteria 核心 (官方 get.hy2.sh, 装最新版; 不做版本锁定, 与 Reality 的
# XRAY_VERSION 锁定不同 —— 官方脚本本身会跳过已是最新版的情况)
# 注意: 不用 bash -c "$(curl ...)" 的写法 —— curl 失败时命令替换为空串, bash -c ""
# 会返回 0, 安装失败被掩盖; 这里先下载到临时文件, 校验下载成功再执行。
_hy2_install_core() {
    echo -e "${yellow}安装 Hysteria2 (官方脚本, 最新版) ...${none}"
    local _tmp_installer
    _tmp_installer=$(mktemp) || return 1
    curl -fsSL https://get.hy2.sh/ -o "$_tmp_installer" 2>/dev/null || { rm -f "$_tmp_installer"; return 1; }
    bash "$_tmp_installer" || { rm -f "$_tmp_installer"; return 1; }
    rm -f "$_tmp_installer"
    HY2_BIN="$(command -v hysteria 2>/dev/null || echo /usr/local/bin/hysteria)"
}

# 生成自签证书 (EC prime256v1, 36500 天). 服务以 hysteria 系统用户运行(非 root),
# 私钥必须让该用户可读: 640 + 属组 hysteria; 取不到服务用户时回退 644 并告警。
# 绝不许用 crazypeace 的 chmod 777。
_hy2_gen_cert() {
    local domain="$1"
    local cert_dir="/etc/ssl/private"
    mkdir -p "$cert_dir" || return 1
    chmod 755 "$cert_dir" 2>/dev/null
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout "${cert_dir}/${domain}.key" -out "${cert_dir}/${domain}.crt" \
        -subj "/CN=${domain}" -days 36500 || return 1
    [[ -f "${cert_dir}/${domain}.crt" && -f "${cert_dir}/${domain}.key" ]] || return 1
    chmod 644 "${cert_dir}/${domain}.crt"
    local svc_user
    svc_user=$(grep -oP '^User=\K\w+' /etc/systemd/system/hysteria-server.service 2>/dev/null | tail -1)
    [[ -z "$svc_user" ]] && svc_user="hysteria"
    if id "$svc_user" >/dev/null 2>&1; then
        chown root:"$svc_user" "${cert_dir}/${domain}.key" 2>/dev/null
        chmod 640 "${cert_dir}/${domain}.key"
    else
        chmod 644 "${cert_dir}/${domain}.key"
        echo -e "${YELLOW}未找到服务用户 ${svc_user}, 私钥暂设 644 以保证服务可读。${NC}"
    fi
}

# 写入 config.yaml (唯一写配置入口, 按 _hy2_* 状态变量渲染整份 YAML, 不许 sed 补丁)
# 证书二选一: acme 内置 ACME / tls 自签; 伪装与混淆互斥, 两者不会同时出现;
# 跳跃开启时 listen 写成 :首-尾 (Hysteria ≥2.8.0 原生段监听)。
_hy2_write_config() {
    mkdir -p /etc/hysteria
    {
        if [[ -n "$_hy2_hop" ]]; then echo "listen: :${_hy2_hop}"; else echo "listen: :${_hy2_port}"; fi
        echo
        if [[ "$_hy2_cert_type" == "acme" ]]; then
            echo "acme:"
            echo "  domains:"
            echo "    - ${_hy2_domain}"
            echo "  email: ${_hy2_email}"
            echo "  type: ${_hy2_acme_type}"
            if [[ "$_hy2_acme_type" == "dns" ]]; then
                echo "  dns:"
                echo "    name: ${_hy2_dns_name}"
                echo "    config:"
                if [[ "$_hy2_dns_name" == "cloudflare" ]]; then
                    echo "      cloudflare_api_token: ${_hy2_dns_token}"
                else
                    echo "      duckdns_api_token: ${_hy2_dns_token}"
                fi
            fi
        else
            echo "tls:"
            echo "  cert: ${_hy2_cert}"
            echo "  key: ${_hy2_key}"
        fi
        echo
        echo "auth:"
        echo "  type: password"
        echo "  password: ${_hy2_password}"
        echo
        echo "ignoreClientBandwidth: true"
        echo
        echo "acl:"
        echo "  inline:"
        echo "    - direct(all)"
        echo
        echo "outbounds:"
        echo "  - name: direct"
        echo "    type: direct"
        echo "  - name: s5_outbound"
        echo "    type: socks5"
        echo "    socks5:"
        echo "      addr: 127.0.0.1:1080"
        if [[ -n "$_hy2_masq_url" ]]; then
            echo
            echo "masquerade:"
            echo "  type: proxy"
            echo "  proxy:"
            echo "    url: ${_hy2_masq_url}"
            echo "    rewriteHost: true"
        fi
        if [[ -n "$_hy2_obfs_pw" ]]; then
            echo
            echo "obfs:"
            echo "  type: salamander"
            echo "  salamander:"
            echo "    password: ${_hy2_obfs_pw}"
        fi
        if [[ "$_hy2_sniff" == "1" ]]; then
            echo
            echo "sniff:"
            echo "  enable: true"
            echo "  timeout: 2s"
            echo "  rewriteDomain: false"
            echo "  tcpPorts: 80,443,8000-9000"
            echo "  udpPorts: all"
        fi
    } > "$HY2_CONFIG"
}

# 改配置统一入口: 备份 -> 写配置 -> 重启 -> 验活; 失败恢复备份 + 重启, 返回 1。
# 注意: 防火墙调整由调用方在 _hy2_apply_config 成功后做, 失败时防火墙保持原样。
_hy2_apply_config() {
    [[ -f "$HY2_CONFIG" ]] && cp -f "$HY2_CONFIG" "${HY2_CONFIG}.bak"
    _hy2_write_config
    _hy2_restart_service
    if _hy2_service_active; then
        return 0
    fi
    echo -e "${RED}Hysteria2 启动失败, 已恢复原配置。${NC}"
    [[ -f "${HY2_CONFIG}.bak" ]] && cp -f "${HY2_CONFIG}.bak" "$HY2_CONFIG"
    _hy2_restart_service
    return 1
}

# 核心版本是否 >= 指定版本 (端口跳跃需 >= 2.8.0 原生段监听)
_hy2_version_ge() {
    local want="$1" v
    v=$("$HY2_BIN" version 2>/dev/null | grep '^Version' | grep -o 'v[.0-9]*' | head -1)
    v="${v#v}"
    [[ -n "$v" ]] || return 1
    [[ "$(printf '%s\n%s\n' "$want" "$v" | sort -V | head -1)" == "$want" ]]
}

# 校验端口 1-65535 (crazypeace 的 case 写法)
_hy2_valid_port() {
    case "$1" in
    [1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5]) return 0 ;;
    *) return 1 ;;
    esac
}

# 完整安装 / 重装. 参数1: auto = 非交互(随机全新节点, 默认端口 2096/域名 learn.microsoft.com)
# 重装固定为自签证书 + 无附加功能 (与 Phase 1 同行为); ACME/伪装/混淆/嗅探/跳跃用菜单开关另行开启。
hy2_install() {
    local mode="${1:-interactive}"
    check_root

    # 已安装则先展示现有配置(不含二维码), 再问是否重装 (回车=是, n=保留退出); auto 直接继续
    if [[ -x "$HY2_BIN" || -f "$HY2_CONFIG" ]]; then
        _hy2_parse_config
        if [[ $_hy2_cfg_valid -eq 1 ]]; then
            hy2_show_config false
            if [[ "$mode" != "auto" ]]; then
                confirm "${YELLOW}检测到已有 Hy2 节点, 是否重装为全新随机节点?${NC}" || {
                    echo -e "${YELLOW}已保留现有节点。${NC}"; return 0; }
            fi
        fi
    fi

    _hy2_deps || { echo -e "${RED}依赖安装失败, 终止。${NC}"; return 1; }
    _hy2_install_core || { echo -e "${RED}Hysteria2 安装失败, 终止。${NC}"; return 1; }

    if ! [[ -x "$HY2_BIN" ]]; then
        echo -e "${RED}Hysteria2 安装失败, 终止。${NC}"
        return 1
    fi

    _hy2_detect_ip
    if [[ -z "$_hy2_ipv4" && -z "$_hy2_ipv6" ]]; then
        echo -e "${YELLOW}未获取到公网 IP, 仍继续安装, 分享链接需稍后手动查看。${NC}"
    fi

    # 重装时先回收旧配置的附加防火墙放行 (跳跃段 / ACME 的 TCP 80), 避免残留
    _hy2_parse_config
    if [[ -n "$_hy2_hop" ]]; then close_firewall_range "${_hy2_hop%-*}" "${_hy2_hop#*-}" udp; fi
    if [[ "$_hy2_cert_type" == "acme" && "$_hy2_acme_type" == "http" ]]; then close_firewall 80 tcp; fi

    local port password domain netstack
    local default_password default_domain
    default_password=$(cat /proc/sys/kernel/random/uuid)
    default_domain="$HY2_DEFAULT_DOMAIN"

    if [[ "$mode" == "auto" ]]; then
        # 非交互: 全部随机 / 默认值
        port="$HY2_DEFAULT_PORT"
        domain="$default_domain"
        password="$default_password"
        netstack=4
        [[ -z "$_hy2_ipv4" && -n "$_hy2_ipv6" ]] && netstack=6
    else
        # 交互: 回车即用默认值
        if [[ -n "$_hy2_ipv4" && -n "$_hy2_ipv6" ]]; then
            read -p "$(echo -e "节点搭在 IPv4 还是 IPv6 上 (默认 ${cyan}4${none}, 输入 6 选 IPv6): ")" netstack
            [ -z "$netstack" ] && netstack=4
            [[ "$netstack" != "4" && "$netstack" != "6" ]] && netstack=4
        elif [[ -n "$_hy2_ipv6" ]]; then
            netstack=6
        else
            netstack=4
        fi

        while :; do
            read -p "$(echo -e "请输入端口 [${magenta}1-65535${none}] (默认 ${cyan}${HY2_DEFAULT_PORT}${none}): ")" port
            [ -z "$port" ] && port="$HY2_DEFAULT_PORT"
            if _hy2_valid_port "$port"; then
                if command -v ss >/dev/null 2>&1 && ss -lun "sport = :${port}" 2>/dev/null | grep -q ":${port}"; then
                    echo -e "${RED}UDP 端口 ${port} 已被占用, 请换一个。${NC}"
                    port=""; continue
                fi
                break
            fi
            echo -e "${RED}输入错误! 端口须为 1-65535。${NC}"
            port=""
        done

        read -p "$(echo -e "请输入密码 (默认随机 ${cyan}${default_password}${none}): ")" password
        [ -z "$password" ] && password="$default_password"
        while ! [[ "$password" =~ ^[A-Za-z0-9._~-]+$ ]]; do
            echo -e "${RED}密码只能含字母/数字/._~- (否则分享链接会断), 请重新输入, 回车用随机密码。${NC}"
            read -p "$(echo -e "请输入密码 (默认随机 ${cyan}${default_password}${none}): ")" password
            [ -z "$password" ] && password="$default_password"
        done

        read -p "$(echo -e "请输入自签证书域名 (默认 ${cyan}${default_domain}${none}): ")" domain
        [ -z "$domain" ] && domain="$default_domain"
        while ! [[ "$domain" =~ ^[a-zA-Z0-9.-]+$ ]]; do
            echo -e "${RED}域名只能含字母/数字/.-, 请重新输入。${NC}"
            read -p "$(echo -e "请输入自签证书域名 (默认 ${cyan}${default_domain}${none}): ")" domain
            [ -z "$domain" ] && domain="$default_domain"
        done
    fi

    _hy2_gen_cert "$domain" || { echo -e "${RED}自签证书生成失败, 终止。${NC}"; return 1; }
    _hy2_port="$port"; _hy2_password="$password"; _hy2_domain="$domain"
    _hy2_cert_type="selfsigned"
    _hy2_cert="/etc/ssl/private/${domain}.crt"; _hy2_key="/etc/ssl/private/${domain}.key"
    _hy2_email=""; _hy2_acme_type="http"; _hy2_dns_name=""; _hy2_dns_token=""
    _hy2_masq_url=""; _hy2_obfs_pw=""; _hy2_sniff=0; _hy2_hop=""
    _hy2_write_config

    # 放行本机防火墙上的 Hy2 端口 (复用 common 的通用放行; Hy2 为 UDP, 与 Reality 的 TCP 不同)
    open_firewall "$port" udp

    echo -e "${yellow}重启 Hysteria2 ...${none}"
    systemctl restart "$HY2_SERVICE" 2>/dev/null || service "$HY2_SERVICE" restart 2>/dev/null
    systemctl enable "$HY2_SERVICE" >/dev/null 2>&1

    if systemctl is-active --quiet "$HY2_SERVICE" 2>/dev/null; then
        echo -e "${green}Hysteria2 安装/更新完成!${none}"
        hy2_show_config "$([[ "$mode" == "auto" ]] && echo false || echo true)"
    else
        echo -e "${RED}Hysteria2 启动失败, 请检查日志: systemctl status ${HY2_SERVICE} --no-pager | tail -20${NC}"
        systemctl status "$HY2_SERVICE" --no-pager 2>/dev/null | tail -20
        return 1
    fi
}

# ACME 真域名证书切换 / 恢复自签. 交互式 (域名/邮箱/验证方式需用户输入)。
# 切换前检查域名解析与 TCP 80 空闲; 改前备份配置, 起服失败恢复备份并回收刚开的 80 放行。
hy2_acme_toggle() {
    check_root
    _hy2_parse_config
    if [[ $_hy2_cfg_valid -ne 1 ]]; then
        echo -e "${RED}未检测到有效的 Hysteria2 配置, 请先安装。${NC}"
        return 1
    fi
    if [[ "$_hy2_cert_type" == "acme" ]]; then
        # 恢复自签: 沿用 ACME 域名作自签 CN
        local domain="$_hy2_domain" old_http=0
        [[ "$_hy2_acme_type" == "http" ]] && old_http=1
        confirm "${YELLOW}当前为 ACME 真域名证书, 是否恢复为自签证书?${NC}" || return 0
        _hy2_gen_cert "$domain" || { echo -e "${RED}自签证书生成失败, 终止。${NC}"; return 1; }
        _hy2_cert_type="selfsigned"
        _hy2_cert="/etc/ssl/private/${domain}.crt"; _hy2_key="/etc/ssl/private/${domain}.key"
        _hy2_email=""; _hy2_acme_type="http"; _hy2_dns_name=""; _hy2_dns_token=""
        if _hy2_apply_config; then
            [[ "$old_http" == "1" ]] && close_firewall 80 tcp
            echo -e "${green}已恢复自签证书。${none}"
            hy2_show_config false
            return 0
        fi
        return 1
    fi
    # 切到 ACME (内置 acme, 不用 acme.sh; 证书由 Hysteria 自己申请/续期)
    local domain email acme_type dns_name dns_token masq_url choice
    while :; do
        read -p "$(echo -e "请输入已解析到本机的域名: ")" domain
        if [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then break; fi
        echo -e "${RED}域名格式不正确, 请重新输入。${NC}"
    done
    read -p "$(echo -e "请输入邮箱 (默认 ${cyan}admin@${domain}${none}): ")" email
    [ -z "$email" ] && email="admin@${domain}"
    while ! [[ "$email" == *@*.* ]]; do
        echo -e "${RED}邮箱格式不正确, 请重新输入。${NC}"
        read -p "$(echo -e "请输入邮箱 (默认 ${cyan}admin@${domain}${none}): ")" email
        [ -z "$email" ] && email="admin@${domain}"
    done
    read -p "$(echo -e "验证方式 (默认 ${cyan}1${none}=HTTP-01 走 TCP 80, 2=DNS-01 Cloudflare, 3=DNS-01 DuckDNS): ")" choice
    [ -z "$choice" ] && choice=1
    acme_type="http"; dns_name=""; dns_token=""
    case "$choice" in
        2) acme_type="dns"; dns_name="cloudflare" ;;
        3) acme_type="dns"; dns_name="duckdns" ;;
        *) acme_type="http" ;;
    esac
    if [[ "$acme_type" == "dns" ]]; then
        echo -e "${YELLOW}DNS-01 需在域名服务商处建最小权限 API Token (Cloudflare: Zone:DNS:Edit)。${NC}"
        while :; do
            read -p "$(echo -e "请输入 ${dns_name} API Token: ")" dns_token
            [[ -n "$dns_token" ]] && break
            echo -e "${RED}Token 不能为空。${NC}"
        done
    fi
    # 伪装站 (混淆开启时不可用, 两者互斥)
    masq_url=""
    if [[ -n "$_hy2_obfs_pw" ]]; then
        echo -e "${YELLOW}当前已开启混淆, 伪装站不可用 (两者互斥)。${NC}"
    else
        local def_masq="${_hy2_masq_url:-$HY2_DEFAULT_MASQ}"
        read -p "$(echo -e "伪装站 URL (默认 ${cyan}${def_masq}${none}, 输入 off 不启用): ")" masq_url
        [ -z "$masq_url" ] && masq_url="$def_masq"
        [[ "$masq_url" == "off" ]] && masq_url=""
    fi
    # 前置检查: 域名解析 + TCP 80 空闲 (仅 HTTP-01)
    _hy2_detect_ip
    local resolved=""
    resolved=$(getent ahosts "$domain" 2>/dev/null | awk '{print $1}' | head -1)
    if [[ -z "$resolved" ]]; then
        echo -e "${YELLOW}域名 ${domain} 解析不到 IP, 请确认 A 记录已指向本机。${NC}"
        confirm "是否仍继续切换 ACME?" || return 0
    elif [[ -n "$_hy2_ipv4" && "$resolved" != "$_hy2_ipv4" ]]; then
        echo -e "${YELLOW}域名解析到 ${resolved}, 本机公网 IP 为 ${_hy2_ipv4}, 不一致, ACME 校验可能失败。${NC}"
        confirm "是否仍继续切换 ACME?" || return 0
    fi
    if [[ "$acme_type" == "http" ]]; then
        if command -v ss >/dev/null 2>&1 && ss -ltn "sport = :80" 2>/dev/null | grep -q ":80[^0-9]"; then
            echo -e "${RED}TCP 80 已被占用, HTTP-01 无法校验。请改用 DNS-01, 或先停掉占 80 的服务。${NC}"
            return 1
        fi
        open_firewall 80 tcp
    fi
    _hy2_cert_type="acme"; _hy2_domain="$domain"; _hy2_email="$email"
    _hy2_acme_type="$acme_type"; _hy2_dns_name="$dns_name"; _hy2_dns_token="$dns_token"
    _hy2_cert=""; _hy2_key=""; _hy2_pin=""
    _hy2_masq_url="$masq_url"
    if _hy2_apply_config; then
        echo -e "${green}ACME 真域名证书已启用, 证书由 Hysteria 自动申请/续期。${none}"
        hy2_show_config false
        return 0
    fi
    [[ "$acme_type" == "http" ]] && close_firewall 80 tcp
    return 1
}

# 伪装站设置 (改地址 / 关闭). 与混淆互斥: 混淆开启时拒绝。
hy2_masquerade() {
    check_root
    _hy2_parse_config
    if [[ $_hy2_cfg_valid -ne 1 ]]; then
        echo -e "${RED}未检测到有效的 Hysteria2 配置, 请先安装。${NC}"
        return 1
    fi
    if [[ -n "$_hy2_obfs_pw" ]]; then
        echo -e "${RED}当前已开启混淆, 伪装站不可用 (两者互斥), 请先关闭混淆。${NC}"
        return 1
    fi
    local url
    if [[ -n "$_hy2_masq_url" ]]; then
        read -p "$(echo -e "伪装站 URL (当前 ${cyan}${_hy2_masq_url}${none}, 回车=保持, off=关闭): ")" url
        [ -z "$url" ] && { echo -e "${YELLOW}伪装站保持不变。${NC}"; return 0; }
        [[ "$url" == "off" ]] && url=""
    else
        read -p "$(echo -e "伪装站 URL (回车=默认 ${cyan}${HY2_DEFAULT_MASQ}${none}, off=保持关闭): ")" url
        [ -z "$url" ] && url="$HY2_DEFAULT_MASQ"
        [[ "$url" == "off" ]] && { echo -e "${YELLOW}伪装站保持关闭。${NC}"; return 0; }
    fi
    if [[ -n "$url" ]] && ! [[ "$url" =~ ^https?://[a-zA-Z0-9.-]+ ]]; then
        echo -e "${RED}URL 须以 http:// 或 https:// 开头。${NC}"
        return 1
    fi
    _hy2_masq_url="$url"
    if _hy2_apply_config; then
        [[ -n "$url" ]] && echo -e "${green}伪装站已设为 ${url}。${none}" || echo -e "${green}伪装站已关闭。${none}"
        hy2_show_config false
        return 0
    fi
    return 1
}

# 混淆 Salamander 开关. 开启时自动移除伪装配置 (两者互斥); 密码本地随机或用户输入。
hy2_obfs_toggle() {
    check_root
    _hy2_parse_config
    if [[ $_hy2_cfg_valid -ne 1 ]]; then
        echo -e "${RED}未检测到有效的 Hysteria2 配置, 请先安装。${NC}"
        return 1
    fi
    if [[ -n "$_hy2_obfs_pw" ]]; then
        confirm "${YELLOW}当前混淆已开启, 是否关闭?${NC}" || return 0
        _hy2_obfs_pw=""
        if _hy2_apply_config; then
            echo -e "${green}混淆已关闭。${none}"
            hy2_show_config false
            return 0
        fi
        return 1
    fi
    local pw_default pw input
    pw_default=$(cat /proc/sys/kernel/random/uuid)
    read -p "$(echo -e "混淆密码 (回车=随机 ${cyan}${pw_default}${none}): ")" input
    pw="${input:-$pw_default}"
    while ! [[ "$pw" =~ ^[A-Za-z0-9._~-]+$ ]]; do
        echo -e "${RED}密码只能含字母/数字/._~- (否则分享链接会断), 请重新输入。${NC}"
        read -p "$(echo -e "混淆密码 (回车=随机 ${cyan}${pw_default}${none}): ")" input
        pw="${input:-$pw_default}"
    done
    echo -e "${YELLOW}注意: 开启混淆后伪装站将失效 (两者互斥), 将自动移除伪装配置。${NC}"
    confirm "确认开启混淆?" || return 0
    _hy2_obfs_pw="$pw"; _hy2_masq_url=""
    if _hy2_apply_config; then
        echo -e "${green}混淆已开启。${none}"
        hy2_show_config false
        return 0
    fi
    return 1
}

# 协议嗅探 Sniff 开关 (整块有无, 默认块照 seagullz4)
hy2_sniff_toggle() {
    check_root
    _hy2_parse_config
    if [[ $_hy2_cfg_valid -ne 1 ]]; then
        echo -e "${RED}未检测到有效的 Hysteria2 配置, 请先安装。${NC}"
        return 1
    fi
    if [[ "$_hy2_sniff" == "1" ]]; then
        confirm "${YELLOW}当前协议嗅探已开启, 是否关闭?${NC}" || return 0
        _hy2_sniff=0
    else
        confirm "是否开启协议嗅探 (Sniff)?" || return 0
        _hy2_sniff=1
    fi
    if _hy2_apply_config; then
        [[ "$_hy2_sniff" == "1" ]] && echo -e "${green}协议嗅探已开启。${none}" || echo -e "${green}协议嗅探已关闭。${none}"
        hy2_show_config false
        return 0
    fi
    return 1
}

# 端口跳跃开关. 用 Hysteria ≥2.8.0 原生 listen: :首-尾 (不写 iptables、不建服务、
# 不写死网口); 防火墙段走 common 的 open/close_firewall_range。
# 关闭跳跃后恢复单端口 = 段首端口; 开关时同步开关防火墙 (只在配置应用成功后动防火墙)。
hy2_hop_toggle() {
    check_root
    _hy2_parse_config
    if [[ $_hy2_cfg_valid -ne 1 ]]; then
        echo -e "${RED}未检测到有效的 Hysteria2 配置, 请先安装。${NC}"
        return 1
    fi
    if [[ -n "$_hy2_hop" ]]; then
        local first="${_hy2_hop%-*}" last="${_hy2_hop#*-}"
        confirm "${YELLOW}当前端口跳跃 ${_hy2_hop}, 是否关闭并恢复单端口 ${_hy2_port}?${NC}" || return 0
        _hy2_hop=""
        if _hy2_apply_config; then
            close_firewall_range "$first" "$last" udp
            open_firewall "$_hy2_port" udp
            echo -e "${green}端口跳跃已关闭。${none}"
            hy2_show_config false
            return 0
        fi
        return 1
    fi
    if ! _hy2_version_ge "$HY2_HOP_MIN_VERSION"; then
        echo -e "${RED}当前核心版本过低, 不支持原生端口跳跃 (需 >= ${HY2_HOP_MIN_VERSION}); 请先重装核心 (菜单 1)。${NC}"
        return 1
    fi
    local first last
    read -p "$(echo -e "跳跃段首端口 (默认 ${cyan}${HY2_DEFAULT_HOP_FIRST}${none}): ")" first
    [ -z "$first" ] && first="$HY2_DEFAULT_HOP_FIRST"
    read -p "$(echo -e "跳跃段尾端口 (默认 ${cyan}${HY2_DEFAULT_HOP_LAST}${none}): ")" last
    [ -z "$last" ] && last="$HY2_DEFAULT_HOP_LAST"
    if ! _hy2_valid_port "$first" || ! _hy2_valid_port "$last" || [[ "$first" -ge "$last" ]]; then
        echo -e "${RED}端口段不正确: 须为 1-65535 且首 < 尾。${NC}"
        return 1
    fi
    _hy2_hop="${first}-${last}"
    if _hy2_apply_config; then
        close_firewall "$_hy2_port" udp
        open_firewall_range "$first" "$last" udp
        echo -e "${green}端口跳跃已开启 (${first}-${last}), 客户端用 mport 参数跳跃。${none}"
        hy2_show_config false
        return 0
    fi
    return 1
}

# 卸载 Hysteria2
hy2_uninstall() {
    check_root
    if [[ ! -x "$HY2_BIN" && ! -f "$HY2_CONFIG" ]]; then
        echo -e "${YELLOW}未检测到 Hysteria2 安装。${NC}"
        return 0
    fi
    confirm "${RED}确定要卸载 Hysteria2 并清理其所有文件?${NC}" || {
        echo -e "${YELLOW}卸载已取消${NC}"; return 0; }

    # 1) 先取出端口/证书域名/跳跃段/ACME 类型(配置删除后就读不到了), 用于回收防火墙放行与删证书
    local old_port old_domain old_cert old_key old_hop old_acme_type old_cert_type
    old_port=$(hy2_get_port)
    _hy2_parse_config
    old_domain="$_hy2_domain"; old_cert="$_hy2_cert"; old_key="$_hy2_key"
    old_hop="$_hy2_hop"; old_acme_type="$_hy2_acme_type"; old_cert_type="$_hy2_cert_type"

    echo -e "${yellow}正在卸载 Hysteria2 ...${none}"
    # 2) 停止并禁用服务
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop "$HY2_SERVICE" >/dev/null 2>&1
        systemctl disable "$HY2_SERVICE" >/dev/null 2>&1
    else
        service "$HY2_SERVICE" stop >/dev/null 2>&1
    fi

    # 3) 官方脚本卸载 (只删二进制与服务单元, 不删配置与 hysteria 用户, 下面手动补)
    # 注意: 不能用 bash -c "$(curl ...)" --remove, --remove 会被当成 $0 而不是参数;
    # 这里先下载到临时文件再带参数执行。
    local _tmp_installer
    _tmp_installer=$(mktemp) || _tmp_installer=""
    if [[ -n "$_tmp_installer" ]] && curl -fsSL https://get.hy2.sh/ -o "$_tmp_installer" 2>/dev/null; then
        bash "$_tmp_installer" --remove >/dev/null 2>&1 || true
        rm -f "$_tmp_installer"
    fi

    # 4) 清理本脚本新增的残留文件 (只删本功能独占的; /etc/ssl/private 为共享目录, 只删本次的两个证书文件)
    rm -rf /etc/hysteria
    [[ -n "$old_cert" ]] && rm -f "$old_cert"
    [[ -n "$old_key" ]] && rm -f "$old_key"
    rm -f "$HY2_INFO" "${HY2_CONFIG}.bak"
    rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/hysteria-server@.service
    rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server.service
    rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server@.service
    # 官方安装器创建的 hysteria 系统用户(家目录 /var/lib/hysteria)仅供本服务使用, 一并清理
    # (ACME 证书存在该家目录下, 随 userdel -r 一并清除)
    if id hysteria >/dev/null 2>&1 && [[ "$(eval echo ~hysteria 2>/dev/null)" == "/var/lib/hysteria" ]]; then
        userdel -r hysteria >/dev/null 2>&1 || true
    fi

    # 5) 回收安装时放行的防火墙端口 (Hy2 为 UDP; 跳跃段与 ACME 的 TCP 80 另行回收)
    [ -n "$old_port" ] && close_firewall "$old_port" udp
    if [[ -n "$old_hop" ]]; then
        close_firewall_range "${old_hop%-*}" "${old_hop#*-}" udp
    fi
    if [[ "$old_cert_type" == "acme" && "$old_acme_type" == "http" ]]; then
        close_firewall 80 tcp
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1
        systemctl reset-failed "$HY2_SERVICE" >/dev/null 2>&1
    fi
    echo -e "${green}Hysteria2 卸载完成, 相关文件已清理。${NC}"
}

# Hysteria2 管理子菜单
hy2_menu() {
    local choice
    while true; do
        clear
        hy2_status_panel
        echo "1. 安装 / 重装 (随机全新节点)"
        echo "2. 查看配置 + 分享链接 + 二维码"
        echo "3. ACME 真域名证书 (切换/恢复自签)"
        echo "4. 伪装站设置"
        echo "5. 混淆 Salamander 开关"
        echo "6. 协议嗅探 Sniff 开关"
        echo "7. 端口跳跃开关"
        echo "8. 卸载 Hysteria2"
        echo "0. 返回主菜单"
        read -p "请输入选项: " choice
        case "$choice" in
            1) hy2_install interactive; read -n 1 -p "按任意键返回 Hysteria2 菜单..." _ ;;
            2) hy2_show_config true; read -n 1 -p "按任意键返回 Hysteria2 菜单..." _ ;;
            3) hy2_acme_toggle; read -n 1 -p "按任意键返回 Hysteria2 菜单..." _ ;;
            4) hy2_masquerade; read -n 1 -p "按任意键返回 Hysteria2 菜单..." _ ;;
            5) hy2_obfs_toggle; read -n 1 -p "按任意键返回 Hysteria2 菜单..." _ ;;
            6) hy2_sniff_toggle; read -n 1 -p "按任意键返回 Hysteria2 菜单..." _ ;;
            7) hy2_hop_toggle; read -n 1 -p "按任意键返回 Hysteria2 菜单..." _ ;;
            8) hy2_uninstall; read -n 1 -p "按任意键返回 Hysteria2 菜单..." _ ;;
            0) break ;;
            *) echo "无效选项"; sleep 1 ;;
        esac
    done
}
