#!/bin/bash
# modules/hy2.sh — Hysteria2 (Hy2) 管理. 依赖 lib/common.sh
# 由 crazypeace/hy2 的极简核心重写并按本项目规范重构而来:
#   官方 get.hy2.sh 装核心 + 自签证书 + 写 /etc/hysteria/config.yaml。
# Phase 1 只做自签证书(不做 ACME/伪装/obfs/端口跳跃, 见 AGENTS.md §8)。
# 端口/密码/证书域名默认随机或默认值, 每次重装为全新节点(与 Reality 同约定)。

# 复用 Reality 原脚本的小写调色命名, 映射到 common.sh 的配色
red="$RED"; green="$GREEN"; yellow="$YELLOW"; magenta="$PURPLE"; cyan="$CYAN"; none="$NC"

HY2_DEFAULT_PORT=2096
HY2_DEFAULT_DOMAIN="learn.microsoft.com"
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

# 解析现有 config.yaml -> _hy2_* 变量; 设置 _hy2_cfg_valid (1=有效)
_hy2_parse_config() {
    _hy2_port=""; _hy2_password=""; _hy2_domain=""; _hy2_cert=""; _hy2_key=""; _hy2_pin=""
    _hy2_cfg_valid=0
    [[ -f "$HY2_CONFIG" ]] || return 1
    _hy2_port=$(hy2_get_port)
    _hy2_password=$(grep -oP '^\s*password:\s*\K\S+' "$HY2_CONFIG" 2>/dev/null | head -1)
    _hy2_cert=$(grep -oP '^\s*cert:\s*\K\S+' "$HY2_CONFIG" 2>/dev/null | head -1)
    _hy2_key=$(grep -oP '^\s*key:\s*\K\S+' "$HY2_CONFIG" 2>/dev/null | head -1)
    if [[ -n "$_hy2_cert" ]]; then
        _hy2_domain=$(basename "$_hy2_cert" .crt)
        if [[ -f "$_hy2_cert" ]]; then
            _hy2_pin=$(openssl x509 -in "$_hy2_cert" -outform DER 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}')
        fi
    fi
    if [[ -n "$_hy2_port" && -n "$_hy2_password" && -n "$_hy2_cert" && -n "$_hy2_key" \
        && -f "$_hy2_cert" && -f "$_hy2_key" ]]; then
        _hy2_cfg_valid=1
    fi
    return 0
}

# 分项检测面板 (统一样式): Hysteria 程序 / 配置 / 配置有效性 / 服务 / 端口监听(UDP)
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
            echo -e "配置解析         : ${GREEN_BOLD}有效的 Hy2 自签配置${NC}"
        else
            echo -e "配置解析         : ${RED_BOLD}无法解析为 Hy2 配置${NC}"
        fi
    else
        echo -e "配置文件         : ${RED_BOLD}不存在${NC}"
    fi
    echo -e "服务状态         : $(svc_status_str "$HY2_SERVICE")"
    echo -e "开机自启         : ${CYAN}$(systemctl is-enabled "$HY2_SERVICE" 2>/dev/null || echo unknown)${NC}"
    echo -e "监听端口(UDP)    : ${CYAN}${port:-未知}${NC}  $(port_listen_udp_str "$port")"
    panel_bot
}

# 查看现有节点配置 + 分享链接. 参数1: true=同时输出二维码 (默认 false)
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
    echo -e "$yellow 地址 (Address) = ${cyan}${ip:-获取失败}$none"
    echo -e "$yellow 端口 (Port) = ${cyan}${_hy2_port}$none"
    echo -e "$yellow 密码 (Password) = ${cyan}${_hy2_password}$none"
    echo -e "$yellow 传输层安全 (TLS) = ${cyan}tls${none}"
    echo -e "$yellow 应用层协议协商 (Alpn) = ${cyan}h3${none}"
    echo -e "$yellow 跳过证书验证 (allowInsecure) = ${cyan}true${none}"
    echo -e "$yellow 证书域名 (SNI) = ${cyan}${_hy2_domain}$none"
    echo -e "$yellow 证书指纹 (pinSHA256) = ${cyan}${_hy2_pin}$none"
    echo -e "${YELLOW}自签证书: 客户端须开 allowInsecure 或校验 pinSHA256; 云服务器另需在安全组放行 UDP ${_hy2_port}。${NC}"
    if [[ -z "$ip" ]]; then
        echo -e "${RED}未获取到公网 IP, 无法生成分享链接。${NC}"
        return 1
    fi
    local url="hysteria2://${_hy2_password}@${disp_ip}:${_hy2_port}?alpn=h3&insecure=1&pinSHA256=${_hy2_pin}#HY2_${ip}"
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

# 写入 config.yaml (需要 port / password / domain)
# 与 crazypeace 的一处偏差: 它的 acl.inline 只有一行被注释掉的规则, 解析后为 null;
# 这里写成显式的 direct(all), 并保留 direct + socks5(127.0.0.1:1080) 两个出站备选。
_hy2_write_config() {
    local port="$1" password="$2" domain="$3"
    mkdir -p /etc/hysteria
    cat > "$HY2_CONFIG" <<-EOF
listen: :${port}

tls:
  cert: /etc/ssl/private/${domain}.crt
  key: /etc/ssl/private/${domain}.key

auth:
  type: password
  password: ${password}

ignoreClientBandwidth: true

acl:
  inline:
    - direct(all)

outbounds:
  - name: direct
    type: direct
  - name: s5_outbound
    type: socks5
    socks5:
      addr: 127.0.0.1:1080
EOF
}

# 校验端口 1-65535 (crazypeace 的 case 写法)
_hy2_valid_port() {
    case "$1" in
    [1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5]) return 0 ;;
    *) return 1 ;;
    esac
}

# 完整安装 / 重装. 参数1: auto = 非交互(随机全新节点, 默认端口 2096/域名 learn.microsoft.com)
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
    _hy2_write_config "$port" "$password" "$domain"

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

# 卸载 Hysteria2
hy2_uninstall() {
    check_root
    if [[ ! -x "$HY2_BIN" && ! -f "$HY2_CONFIG" ]]; then
        echo -e "${YELLOW}未检测到 Hysteria2 安装。${NC}"
        return 0
    fi
    confirm "${RED}确定要卸载 Hysteria2 并清理其所有文件?${NC}" || {
        echo -e "${YELLOW}卸载已取消${NC}"; return 0; }

    # 1) 先取出端口与证书域名(配置删除后就读不到了), 用于回收防火墙放行与删证书
    local old_port old_domain old_cert old_key
    old_port=$(hy2_get_port)
    _hy2_parse_config
    old_domain="$_hy2_domain"; old_cert="$_hy2_cert"; old_key="$_hy2_key"

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
    rm -f "$HY2_INFO"
    rm -f /etc/systemd/system/hysteria-server.service /etc/systemd/system/hysteria-server@.service
    rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server.service
    rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server@.service
    # 官方安装器创建的 hysteria 系统用户(家目录 /var/lib/hysteria)仅供本服务使用, 一并清理
    if id hysteria >/dev/null 2>&1 && [[ "$(eval echo ~hysteria 2>/dev/null)" == "/var/lib/hysteria" ]]; then
        userdel -r hysteria >/dev/null 2>&1 || true
    fi

    # 5) 回收安装时放行的防火墙端口 (Hy2 为 UDP)
    [ -n "$old_port" ] && close_firewall "$old_port" udp

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
        echo "3. 卸载 Hysteria2"
        echo "0. 返回主菜单"
        read -p "请输入选项: " choice
        case "$choice" in
            1) hy2_install interactive; read -n 1 -p "按任意键返回 Hysteria2 菜单..." _ ;;
            2) hy2_show_config true; read -n 1 -p "按任意键返回 Hysteria2 菜单..." _ ;;
            3) hy2_uninstall; read -n 1 -p "按任意键返回 Hysteria2 菜单..." _ ;;
            0) break ;;
            *) echo "无效选项"; sleep 1 ;;
        esac
    done
}
