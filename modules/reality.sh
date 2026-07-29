#!/bin/bash
# modules/reality.sh — VLESS + Reality (Xray) 管理. 依赖 lib/common.sh
# 由独立的 reality 一键脚本重构合并而来: UUID/密钥/ShortID 默认随机,
# 运行前分项检测面板, 查看配置(含分享链接, 可选二维码), 安装/重装, 卸载。

# 复用 reality 原脚本的小写调色命名, 映射到 common.sh 的配色
red="$RED"; green="$GREEN"; yellow="$YELLOW"; magenta="$PURPLE"; cyan="$CYAN"; none="$NC"

XRAY_VERSION="v25.10.15"

_reality_pause() {
    read -rsp "$(echo -e "按 $green Enter 回车键 $none 继续....或按 $red Ctrl + C $none 取消.")" -d $'\n'
    echo
}

# 探测公网 IP -> 设置 IPv4 / IPv6
_reality_detect_ip() {
    IPv4=""; IPv6=""
    local InFaces i p4 p6
    InFaces=($(ls /sys/class/net/ 2>/dev/null | grep -E '^(eth|ens|eno|esp|enp|venet|vif)'))
    for i in "${InFaces[@]}"; do
        p4=$(curl -4s --interface "$i" -m 2 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -oP "ip=\K.*$")
        p6=$(curl -6s --interface "$i" -m 2 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -oP "ip=\K.*$")
        [[ -n "$p4" ]] && IPv4="$p4"
        [[ -n "$p6" ]] && IPv6="$p6"
    done
}

# 解析现有 config.json -> exist_* 变量; 设置 _reality_cfg_valid (1=有效)
_reality_parse_config() {
    exist_uuid=""; exist_port=""; exist_domain=""; exist_privkey=""; exist_shortid=""; exist_pubkey=""
    _reality_cfg_valid=0
    [[ -f "$REALITY_CONFIG" ]] || return 1
    exist_uuid=$(grep -oP '"id"\s*:\s*"\K[0-9a-fA-F-]{36}' "$REALITY_CONFIG" | head -1)
    exist_port=$(grep -oP '"port"\s*:\s*\K[0-9]+(?=\s*,?\s*//\s*\*\*\*)' "$REALITY_CONFIG" | head -1)
    [[ -z "$exist_port" ]] && exist_port=$(sed -E 's#//.*$##' "$REALITY_CONFIG" | grep -oP '"port"\s*:\s*\K[0-9]+' | head -1)
    exist_domain=$(grep -oP '"serverNames"\s*:\s*\[\s*"\K[^"]+' "$REALITY_CONFIG" | head -1)
    exist_privkey=$(grep -oP '"privateKey"\s*:\s*"\K[^"]+' "$REALITY_CONFIG" | head -1)
    exist_shortid=$(grep -oP '"shortIds"\s*:\s*\[\s*"\K[^"]*' "$REALITY_CONFIG" | head -1)
    if grep -q '"protocol"[[:space:]]*:[[:space:]]*"vless"' "$REALITY_CONFIG" \
        && grep -q '"security"[[:space:]]*:[[:space:]]*"reality"' "$REALITY_CONFIG" \
        && [[ -n "$exist_uuid" && -n "$exist_privkey" ]]; then
        _reality_cfg_valid=1
        if [[ -x "$REALITY_BIN" ]]; then
            local t
            t=$(echo -n ${exist_privkey} | xargs "$REALITY_BIN" x25519 -i 2>/dev/null)
            exist_pubkey=$(echo ${t} | awk '{print $4}')
        fi
    fi
    return 0
}

# 分项检测面板 (统一样式): Xray 程序 / 配置 / 配置有效性 / 服务 / 端口监听
reality_status_panel() {
    local xver=""
    [[ -x "$REALITY_BIN" ]] && xver=$("$REALITY_BIN" version 2>/dev/null | head -1 | awk '{print $2}')
    _reality_parse_config
    local port; port=$(reality_get_port)
    panel_top "Reality 环境检测"
    if [[ -x "$REALITY_BIN" ]]; then
        echo -e "Xray 程序        : ${GREEN_BOLD}已安装 (v${xver})${NC}"
    else
        echo -e "Xray 程序        : ${RED_BOLD}未安装${NC}"
    fi
    if [[ -f "$REALITY_CONFIG" ]]; then
        echo -e "配置文件         : ${GREEN_BOLD}已存在${NC}"
        if [[ $_reality_cfg_valid -eq 1 ]]; then
            echo -e "配置解析         : ${GREEN_BOLD}有效的 VLESS Reality${NC}"
        else
            echo -e "配置解析         : ${RED_BOLD}无法解析为 VLESS Reality${NC}"
        fi
    else
        echo -e "配置文件         : ${RED_BOLD}不存在${NC}"
    fi
    echo -e "服务状态         : $(svc_status_str xray)"
    echo -e "开机自启         : ${CYAN}$(systemctl is-enabled xray 2>/dev/null || echo unknown)${NC}"
    echo -e "监听端口         : ${CYAN}${port:-未知}${NC}  $(port_listen_str "$port")"
    panel_bot
}

# 查看现有节点配置 + 分享链接. 参数1: true=同时输出二维码 (默认 false)
reality_show_config() {
    local show_qr="${1:-false}"
    _reality_parse_config
    if [[ $_reality_cfg_valid -ne 1 ]]; then
        echo -e "${RED}未检测到有效的 Reality 配置。${NC}"
        return 1
    fi
    _reality_detect_ip
    local ip="" netstack="" disp_ip
    if [[ -n "$IPv4" ]]; then ip="$IPv4"; netstack=4
    elif [[ -n "$IPv6" ]]; then ip="$IPv6"; netstack=6; fi
    disp_ip="$ip"; [[ "$netstack" == "6" ]] && disp_ip="[$ip]"

    echo -e "${BLUE}---------- Reality 节点配置 ----------${NC}"
    echo -e "$yellow 地址 (Address) = ${cyan}${ip}${none}"
    echo -e "$yellow 端口 (Port) = ${cyan}${exist_port}${none}"
    echo -e "$yellow 用户ID (UUID) = ${cyan}${exist_uuid}${none}"
    echo -e "$yellow 流控 (Flow) = ${cyan}xtls-rprx-vision${none}"
    echo -e "$yellow 加密 (Encryption) = ${cyan}none${none}"
    echo -e "$yellow 传输协议 (Network) = ${cyan}tcp${none}"
    echo -e "$yellow 底层传输安全 (TLS) = ${cyan}reality${none}"
    echo -e "$yellow SNI = ${cyan}${exist_domain}${none}"
    echo -e "$yellow 指纹 (Fingerprint) = ${cyan}random${none}"
    echo -e "$yellow 公钥 (PublicKey) = ${cyan}${exist_pubkey}${none}"
    echo -e "$yellow ShortId = ${cyan}${exist_shortid}${none}"
    local url="vless://${exist_uuid}@${disp_ip}:${exist_port}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${exist_domain}&fp=random&pbk=${exist_pubkey}&sid=${exist_shortid}&spx=&#VLESS_R_${disp_ip}"
    echo -e "$green 分享链接 (Share Link): $none"
    echo -e "${cyan}${url}${none}"
    echo "$url" > ~/_vless_reality_url_ 2>/dev/null
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
_reality_deps() {
    install_package_if_missing curl >/dev/null 2>&1 || true
    install_package_if_missing wget >/dev/null 2>&1 || true
    install_package_if_missing qrencode >/dev/null 2>&1 || true
}

# 安装 / 更新 Xray 核心
_reality_install_core() {
    echo -e "${yellow}安装 Xray ${XRAY_VERSION} ...${none}"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version "$XRAY_VERSION"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-geodata
    REALITY_BIN="$(command -v xray 2>/dev/null || echo /usr/local/bin/xray)"
}

# 写入 config.json (需要 port / uuid / domain / private_key / shortid)
_reality_write_config() {
    local port="$1" uuid="$2" domain="$3" private_key="$4" shortid="$5"
    mkdir -p /usr/local/etc/xray
    cat > "$REALITY_CONFIG" <<-EOF
{ // VLESS + Reality
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${port},    // ***
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",    // ***
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${domain}:443",    // ***
          "xver": 0,
          "serverNames": ["${domain}"],    // ***
          "privateKey": "${private_key}",    // ***私钥
          "shortIds": ["${shortid}"]    // ***
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],
  "dns": {
    "servers": [
      "8.8.8.8",
      "1.1.1.1",
      "2001:4860:4860::8888",
      "2606:4700:4700::1111",
      "localhost"
    ]
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "block"
      }
    ]
  }
}
EOF
}

# 完整安装 / 重装. 参数1: auto = 非交互(随机全新节点, 默认端口443/SNI learn.microsoft.com)
reality_install() {
    local mode="${1:-interactive}"
    check_root

    _reality_deps
    _reality_install_core

    if ! [[ -x "$REALITY_BIN" ]]; then
        echo -e "${RED}Xray 安装失败, 终止。${NC}"
        return 1
    fi

    _reality_detect_ip
    local ip netstack
    if [[ -n "$IPv4" ]]; then ip="$IPv4"; netstack=4
    elif [[ -n "$IPv6" ]]; then ip="$IPv6"; netstack=6
    else echo -e "${RED}未获取到公网 IP。${NC}"; fi

    local port uuid domain private_key public_key shortid tmp_key default_uuid default_private_key default_public_key default_shortid

    default_uuid=$(cat /proc/sys/kernel/random/uuid)

    if [[ "$mode" == "auto" ]]; then
        # 非交互: 全部随机 / 默认值
        port=443
        domain="learn.microsoft.com"
        uuid="$default_uuid"
        tmp_key=$("$REALITY_BIN" x25519)
        private_key=$(echo ${tmp_key} | awk '{print $2}')
        public_key=$(echo ${tmp_key} | awk '{print $4}')
        shortid=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
    else
        # 交互: 回车即用随机默认值
        local default_port=443
        read -p "$(echo -e "请输入端口 Port (默认 ${cyan}${default_port}${none}): ")" port
        [ -z "$port" ] && port=$default_port

        read -p "$(echo -e "请输入 UUID (默认随机 ${cyan}${default_uuid}${none}): ")" uuid
        [ -z "$uuid" ] && uuid=$default_uuid

        tmp_key=$("$REALITY_BIN" x25519)
        default_private_key=$(echo ${tmp_key} | awk '{print $2}')
        default_public_key=$(echo ${tmp_key} | awk '{print $4}')
        read -p "$(echo -e "请输入 x25519 私钥 (默认随机 ${cyan}${default_private_key}${none}): ")" private_key
        if [[ -z "$private_key" ]]; then
            private_key=$default_private_key
            public_key=$default_public_key
        else
            tmp_key=$(echo -n ${private_key} | xargs "$REALITY_BIN" x25519 -i)
            private_key=$(echo ${tmp_key} | awk '{print $2}')
            public_key=$(echo ${tmp_key} | awk '{print $4}')
        fi

        default_shortid=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
        read -p "$(echo -e "请输入 ShortID (默认随机 ${cyan}${default_shortid}${none}): ")" shortid
        [ -z "$shortid" ] && shortid=$default_shortid

        read -p "$(echo -e "请输入伪装域名 SNI (默认 ${cyan}learn.microsoft.com${none}): ")" domain
        [ -z "$domain" ] && domain="learn.microsoft.com"
    fi

    _reality_write_config "$port" "$uuid" "$domain" "$private_key" "$shortid"

    # 放行本机防火墙上的 Reality 端口 (复用 common 的通用放行; Reality 为 TCP)
    open_firewall "$port" tcp

    echo -e "${yellow}重启 Xray ...${none}"
    systemctl restart xray 2>/dev/null || service xray restart 2>/dev/null
    systemctl enable xray >/dev/null 2>&1

    echo -e "${green}Reality 安装/更新完成!${none}"
    reality_show_config "$([[ "$mode" == "auto" ]] && echo false || echo true)"
}

# 卸载 Reality (Xray)
reality_uninstall() {
    check_root
    if [[ ! -f /usr/local/bin/xray && ! -f "$REALITY_CONFIG" ]]; then
        echo -e "${YELLOW}未检测到 Xray 安装。${none}"
        return 0
    fi
    confirm "${RED}确定要卸载 Reality (Xray) 并清理其所有文件?${NC}" || {
        echo -e "${YELLOW}卸载已取消${NC}"; return 0; }

    # 1) 先取出端口(配置删除后就读不到了), 用于回收防火墙放行
    local old_port; old_port=$(reality_get_port)

    echo -e "${yellow}正在卸载 Xray / Reality ...${none}"
    # 2) 停止并禁用服务
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop xray >/dev/null 2>&1
        systemctl disable xray >/dev/null 2>&1
    else
        service xray stop >/dev/null 2>&1
    fi

    # 3) 官方脚本彻底卸载 (含二进制/服务单元/geodata)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge 2>/dev/null

    # 4) 清理本脚本新增的残留文件
    rm -f "$REALITY_CONFIG" ~/_vless_reality_url_
    rm -rf /usr/local/etc/xray /usr/local/share/xray /var/log/xray
    rm -f /etc/systemd/system/xray.service /etc/systemd/system/xray@.service
    rm -rf /etc/systemd/system/xray.service.d /etc/systemd/system/xray@.service.d

    # 5) 回收安装时放行的防火墙端口
    [ -n "$old_port" ] && close_firewall "$old_port" tcp

    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1
        systemctl reset-failed xray >/dev/null 2>&1
    fi
    echo -e "${green}Reality (Xray) 卸载完成, 相关文件已清理。${none}"
}

# Reality 管理子菜单
reality_menu() {
    local choice
    while true; do
        clear
        reality_status_panel
        echo "1. 安装 / 重装 (随机全新节点)"
        echo "2. 查看配置 + 分享链接 + 二维码"
        echo "3. 卸载 Reality"
        echo "0. 返回主菜单"
        read -p "请输入选项: " choice
        case "$choice" in
            1) reality_install interactive; read -n 1 -p "按任意键返回 Reality 菜单..." _ ;;
            2) reality_show_config true; read -n 1 -p "按任意键返回 Reality 菜单..." _ ;;
            3) reality_uninstall; read -n 1 -p "按任意键返回 Reality 菜单..." _ ;;
            0) break ;;
            *) echo "无效选项"; sleep 1 ;;
        esac
    done
}
