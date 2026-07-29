#!/bin/bash
# modules/ssh.sh — SSH 安全管理 (密钥登录 / 端口). 依赖 lib/common.sh

# SSH 状态检测面板 (统一样式)
ssh_status_panel() {
    detect_os
    local root_login pwd_auth ports
    root_login=$(grep "^PermitRootLogin" "$SSH_CONF" 2>/dev/null | awk '{print $2}'); [ -z "$root_login" ] && root_login="默认(prohibit-password)"
    pwd_auth=$(grep "^PasswordAuthentication" "$SSH_CONF" 2>/dev/null | awk '{print $2}'); [ -z "$pwd_auth" ] && pwd_auth="yes(默认)"
    ports=$(grep "^Port " "$SSH_CONF" 2>/dev/null | awk '{print $2}' | xargs); [ -z "$ports" ] && ports="22(默认)"
    panel_top "SSH 状态检测"
    if [[ "$root_login" =~ ^(yes|YES)$ ]]; then
        echo -e "Root 登录        : ${GREEN_BOLD}${root_login}${NC}"
    else
        echo -e "Root 登录        : ${RED_BOLD}${root_login}${NC}"
    fi
    if [[ "$pwd_auth" =~ ^(no|NO)$ ]]; then
        echo -e "密码验证         : ${GREEN_BOLD}${pwd_auth}${NC}"
    else
        echo -e "密码验证         : ${RED_BOLD}${pwd_auth}${NC}"
    fi
    echo -e "SSH 端口         : ${CYAN}${ports}${NC}"
    if [ -f "$AUTH_KEYS" ]; then
        echo -e "密钥文件         : ${GREEN_BOLD}已存在${NC}"
    else
        echo -e "密钥文件         : ${RED_BOLD}不存在${NC}"
    fi
    echo -e "SSH 服务         : $(svc_status_str "${SERVICE_NAME:-ssh}")"
    if [ -d /run/sshd ]; then
        echo -e "运行时目录       : ${GREEN_BOLD}/run/sshd 正常${NC}"
    else
        echo -e "运行时目录       : ${RED_BOLD}/run/sshd 缺失 (会导致 sshd -t 失败, 可自动修复)${NC}"
    fi
    if ssh_is_socket_activated 2>/dev/null; then
        echo -e "激活方式         : ${CYAN}systemd socket (${SERVICE_NAME}.socket)${NC}"
    else
        echo -e "激活方式         : ${CYAN}传统 service${NC}"
    fi
    panel_bot
}

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

    # 检查 socket 单元是否存在
    if ! systemctl list-unit-files "$socket_unit" >/dev/null 2>&1; then
        return 0
    fi

    # 检查是否启用
    if ! systemctl is-enabled "$socket_unit" >/dev/null 2>&1 && ! systemctl is-active "$socket_unit" >/dev/null 2>&1; then
        return 0
    fi

    # 获取当前监听端口
    current_ports=$(systemctl show -p Listen "$socket_unit" 2>/dev/null | sed 's/^Listen=//')

    # 【关键修复区】采用最稳健的空格分割遍历，彻底避开 <<< 和 tr 引发的解析错误
    if [ -n "$current_ports" ]; then
        for p_item in $current_ports; do
            # 提取端口号 (处理类似 [::]:22 或 0.0.0.0:22 的格式)
            port=$(echo "$p_item" | sed 's/.*://')
            if [[ "$port" =~ ^[0-9]+$ ]]; then
                final_ports+=("$port")
            fi
        done
    fi

    # 根据模式（追加或替换）处理端口数组
    if [[ "$mode" =~ ^[Aa]$ ]]; then
        if [ ${#final_ports[@]} -eq 0 ]; then
            final_ports=("22")
        fi
        # 如果新端口不在数组中，则添加
        local found=0
        for p in "${final_ports[@]}"; do
            [[ "$p" == "$new_port" ]] && found=1
        done
        if [ "$found" -eq 0 ]; then
            final_ports+=("$new_port")
        fi
    else
        # 替换模式，只保留新端口
        final_ports=("$new_port")
    fi

    # 【关键】端口去重: systemctl show -p Listen 会把同一端口的 IPv4/IPv6 各列一次,
    # 若不去重就会写出重复的 ListenStream, systemd 重复绑定同一端口 →
    # "Address already in use" → socket 启动失败 → ssh.service 依赖失败 → SSH 整体不可用。
    local uniq_ports=() q seen
    for p in "${final_ports[@]}"; do
        seen=0
        for q in "${uniq_ports[@]}"; do [ "$q" = "$p" ] && { seen=1; break; }; done
        [ "$seen" -eq 0 ] && uniq_ports+=("$p")
    done
    final_ports=("${uniq_ports[@]}")

    # 写入配置
    mkdir -p "$dropin_dir"
    {
        echo "[Socket]"
        echo "ListenStream="
        for p in "${final_ports[@]}"; do
            echo "ListenStream=${p}"
        done
    } > "$override_file"

    systemctl daemon-reload
    echo -e "${GREEN}  ✓ 已更新 ${socket_unit} 的监听端口: ${final_ports[*]}${NC}"
} # <--- 确保函数闭合

# ---------- 安全应用层: 备份 / 校验 / 重启 / 回滚 (防止 SSH 锁死) ----------
SSH_LAST_BACKUP=""
SSH_KEEP_FILE=""

# 改动前备份 sshd_config + drop-in + socket override 到时间戳压缩包
ssh_backup() {
    local ts; ts=$(date +%Y%m%d%H%M%S)
    mkdir -p /root/.ssh_cmd_backups
    SSH_LAST_BACKUP="/root/.ssh_cmd_backups/ssh_${ts}.tar.gz"
    tar czf "$SSH_LAST_BACKUP" \
        "$SSH_CONF" \
        /etc/ssh/sshd_config.d \
        "/etc/systemd/system/${SERVICE_NAME}.socket.d" 2>/dev/null
    echo -e "${BLUE}  已备份当前 SSH 配置: ${SSH_LAST_BACKUP}${NC}"
}

# 判断当前是否为 systemd socket 激活模式 (Ubuntu 22.10+/24.04 默认 ssh.socket)
ssh_is_socket_activated() {
    systemctl list-unit-files "${SERVICE_NAME}.socket" >/dev/null 2>&1 || return 1
    systemctl is-active --quiet "${SERVICE_NAME}.socket" 2>/dev/null
}

# 按激活方式重启正确的单元: socket 激活则重启 .socket, 否则重启 .service
_ssh_restart_units() {
    systemctl daemon-reload >/dev/null 2>&1
    if ssh_is_socket_activated; then
        systemctl restart "${SERVICE_NAME}.socket" >/dev/null 2>&1
    else
        systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || service "$SERVICE_NAME" restart >/dev/null 2>&1
    fi
}

# 判断 SSH 是否可服务: socket 激活时 .service 常为 inactive 属正常, 故以 .socket 为准
_ssh_primary_active() {
    if ssh_is_socket_activated; then
        return 0
    fi
    systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null
}

# 本机 TCP 自连测试: 真正对新端口建连一次 (优先 bash /dev/tcp, 回退 nc)。0=成功
_ssh_tcp_check() {
    local port="$1" host to=""
    command -v timeout >/dev/null 2>&1 && to="timeout 3"
    for host in 127.0.0.1 ::1; do
        if $to bash -c "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null; then
            return 0
        fi
    done
    if command -v nc >/dev/null 2>&1; then
        nc -z -w 3 127.0.0.1 "$port" >/dev/null 2>&1 && return 0
        nc -z -w 3 ::1 "$port" >/dev/null 2>&1 && return 0
    fi
    return 1
}

# (通用放行函数 open_firewall 已移至 lib/common.sh, 供各功能复用)

# ---------- sshd 运行时环境自愈 ----------
# 背景: 以下情况会让 `sshd -t` 失败, 但它们都不是配置语法问题, 改配置文件毫无用处:
#   - Missing privilege separation directory: /run/sshd  (/run 是 tmpfs, 重启即清空)
#   - Could not load host key: /etc/ssh/ssh_host_*_key   (主机密钥缺失)
# 因此必须先区分“运行时问题”与“真正的配置错误”, 否则会误判并触发无意义的回滚/恢复。

# 确保 sshd 特权分离目录存在, 并让其在重启后自动创建
_ssh_ensure_runtime_dir() {
    local d=/run/sshd
    if [ ! -d "$d" ]; then
        mkdir -p "$d" 2>/dev/null
        chmod 0755 "$d" 2>/dev/null
        chown root:root "$d" 2>/dev/null
        if [ -d "$d" ]; then
            echo -e "${GREEN}  ✓ 已创建缺失的运行时目录 ${d}${NC}"
        else
            echo -e "${RED}  ✗ 无法创建 ${d} (权限不足?)${NC}"
            return 1
        fi
    fi
    # /run 为 tmpfs, 重启会清空; 用 tmpfiles.d 规则保证开机自动重建
    if [ -d /etc/tmpfiles.d ] && [ ! -f /etc/tmpfiles.d/cmd-sshd-runtime.conf ]; then
        if echo 'd /run/sshd 0755 root root -' > /etc/tmpfiles.d/cmd-sshd-runtime.conf 2>/dev/null; then
            echo -e "${GREEN}  ✓ 已添加 tmpfiles 规则, 重启后自动重建 ${d}${NC}"
        fi
    fi
    return 0
}

# 针对 sshd -t 输出里的运行时问题做自动修复; 修复了任意一项返回 0
_ssh_fix_runtime_issue() {
    local out="$1" fixed=1
    if echo "$out" | grep -qi 'privilege separation directory'; then
        echo -e "${BLUE}  检测到运行时目录缺失(非配置错误), 正在修复...${NC}"
        _ssh_ensure_runtime_dir && fixed=0
    fi
    if echo "$out" | grep -qi 'Could not load host key'; then
        echo -e "${BLUE}  检测到主机密钥缺失(非配置错误), 正在生成 (ssh-keygen -A)...${NC}"
        if ssh-keygen -A >/dev/null 2>&1; then
            echo -e "${GREEN}  ✓ 已生成缺失的主机密钥${NC}"
            fixed=0
        fi
    fi
    return $fixed
}

# 校验 sshd 配置并分类; 对运行时问题会先自愈再复检
# 返回: 0=通过  1=真正的配置错误  2=运行时问题且自愈失败
# 输出留在 SSH_SSHDT_OUT
_ssh_config_test() {
    local sshd_bin out rc
    sshd_bin="$(command -v sshd || echo /usr/sbin/sshd)"
    if [ ! -x "$sshd_bin" ]; then
        SSH_SSHDT_OUT="sshd 程序不存在"
        return 1
    fi
    out=$("$sshd_bin" -t 2>&1); rc=$?
    SSH_SSHDT_OUT="$out"
    [ $rc -eq 0 ] && return 0

    # 属于可自愈的运行时问题 -> 修复后复检
    if echo "$out" | grep -qiE 'privilege separation directory|Could not load host key'; then
        if _ssh_fix_runtime_issue "$out"; then
            out=$("$sshd_bin" -t 2>&1); rc=$?
            SSH_SSHDT_OUT="$out"
            [ $rc -eq 0 ] && { echo -e "${GREEN}  ✓ 运行时问题已修复, 配置校验通过${NC}"; return 0; }
            echo "$out" | grep -qiE 'privilege separation directory|Could not load host key' && return 2
            return 1
        fi
        return 2
    fi
    return 1
}

# ---------- 准确判定“SSH 到底通不通” (避免误报) ----------
# 当前实际生效的方式: socket / service / none
# 关键: socket 与 service 只要任一 active 即视为正常 —— 不能只看其中一个,
#       否则 socket 单元为 static/indirect 而实际跑 service 的机器会被误报。
_ssh_active_mode() {
    command -v systemctl >/dev/null 2>&1 || { echo none; return; }
    if systemctl is-active --quiet "${SERVICE_NAME}.socket" 2>/dev/null; then echo socket; return; fi
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then echo service; return; fi
    echo none
}

# 取“真正生效”的 SSH 端口: 优先 sshd -T(会解析 Include/Match),
# 再叠加 socket 单元的 ListenStream(Ubuntu 22.10+/24.04 端口在此), 最后兜底 22
_ssh_effective_ports() {
    local ports="" sshd_bin p item
    sshd_bin="$(command -v sshd || echo /usr/sbin/sshd)"
    if [ -x "$sshd_bin" ]; then
        ports=$("$sshd_bin" -T 2>/dev/null | awk '/^port /{print $2}')
    fi
    if [ -z "$ports" ]; then
        ports=$(grep -hE '^[[:space:]]*Port[[:space:]]+[0-9]+' "$SSH_CONF" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}')
    fi
    if command -v systemctl >/dev/null 2>&1; then
        for item in $(systemctl show -p Listen "${SERVICE_NAME}.socket" 2>/dev/null | sed 's/^Listen=//'); do
            p=$(echo "$item" | sed 's/.*://')
            [[ "$p" =~ ^[0-9]+$ ]] && ports="${ports} ${p}"
        done
    fi
    [ -z "${ports// /}" ] && ports=22
    echo "$ports" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -u | tr '\n' ' '
}

# SSH 是否确实在监听。0=在监听/无法判定, 1=确认没有监听
_ssh_listening_ok() {
    # socket 处于 active 时, 监听套接字由 systemd 持有, 按定义即可接受连接
    [ "$(_ssh_active_mode)" = "socket" ] && return 0
    command -v ss >/dev/null 2>&1 || return 0   # 无 ss, 不做判定(不误报)
    local p
    for p in $(_ssh_effective_ports); do
        ss -ltn "sport = :${p}" 2>/dev/null | grep -q "LISTEN" && return 0
    done
    # 兜底: 存在由 sshd 持有的监听套接字(端口可能来自本函数未覆盖的来源)
    ss -ltnp 2>/dev/null | grep -q 'sshd' && return 0
    return 1
}

# 修正 socket override 中重复的 ListenStream (重复绑定会导致 Address already in use)
# 返回 0=发现并已修正 / 1=无需修正或无法修正
_ssh_fix_socket_override() {
    local f="/etc/systemd/system/${SERVICE_NAME}.socket.d/override.conf"
    [ -f "$f" ] || return 1
    local ports p q seen uniq=() n_all n_uniq
    ports=$(grep -E '^[[:space:]]*ListenStream=[0-9]+' "$f" 2>/dev/null | sed 's/.*ListenStream=//')
    [ -z "$ports" ] && return 1
    for p in $ports; do
        seen=0
        for q in "${uniq[@]}"; do [ "$q" = "$p" ] && { seen=1; break; }; done
        [ "$seen" -eq 0 ] && uniq+=("$p")
    done
    n_all=$(echo "$ports" | wc -w | tr -d ' '); n_uniq=${#uniq[@]}
    [ "$n_all" -eq "$n_uniq" ] && return 1     # 没有重复
    {
        echo "[Socket]"
        echo "ListenStream="
        for p in "${uniq[@]}"; do echo "ListenStream=${p}"; done
    } > "$f"
    systemctl daemon-reload >/dev/null 2>&1
    systemctl reset-failed "${SERVICE_NAME}.socket" "$SERVICE_NAME" >/dev/null 2>&1
    echo -e "${GREEN}  ✓ 已修正 ${SERVICE_NAME}.socket 中重复的监听端口 (${n_all} 项 → ${n_uniq} 项: ${uniq[*]})${NC}"
    return 0
}

# 从最近一次备份回滚 (清除新增 socket drop-in, 按激活方式重启)
ssh_restore() {
    if [ -z "$SSH_LAST_BACKUP" ] || [ ! -f "$SSH_LAST_BACKUP" ]; then
        echo -e "${RED}  无可用备份, 无法自动回滚, 请手动检查 $SSH_CONF${NC}"
        return 1
    fi
    systemctl revert "${SERVICE_NAME}.socket" >/dev/null 2>&1
    tar xzf "$SSH_LAST_BACKUP" -C / >/dev/null 2>&1
    _ssh_restart_units
    echo -e "${YELLOW}  已回滚到改动前的 SSH 配置。${NC}"
}

# 校验(sshd -t) → 按激活方式重启 → 验证可服务; 任一失败则自动回滚。返回 0/1
ssh_safe_apply() {
    echo -e "${BLUE}正在校验 SSH 配置 (sshd -t)...${NC}"
    # 先确保运行时目录存在, 避免 /run/sshd 缺失导致的假失败
    _ssh_ensure_runtime_dir >/dev/null 2>&1
    if ! _ssh_config_test; then
        echo -e "${RED}配置校验失败:${NC}"
        echo "$SSH_SSHDT_OUT" | head -5 | sed 's/^/  /'
        ssh_restore
        return 1
    fi
    if ssh_is_socket_activated; then
        echo -e "${BLUE}检测到 systemd socket 激活 (${SERVICE_NAME}.socket): 端口由 socket 控制, 正在重启 socket 使其生效...${NC}"
    fi
    _ssh_restart_units
    sleep 1
    if command -v systemctl >/dev/null 2>&1 && ! _ssh_primary_active; then
        echo -e "${RED}SSH 重启后未处于可服务状态, 正在回滚...${NC}"
        ssh_restore
        return 1
    fi
    echo -e "${GREEN}SSH 配置已生效 (现有会话不会中断)。${NC}"
    return 0
}

# 定时自动回滚: secs 秒后若未见“确认文件”则恢复原配置 (防止误配置锁死)
ssh_arm_autorollback() {
    local secs="${1:-120}"
    [ -n "$SSH_LAST_BACKUP" ] && [ -f "$SSH_LAST_BACKUP" ] || return 0
    local keep="/tmp/.ssh_keep_$(date +%s)_$$"
    local runner="/tmp/.ssh_rollback_$(date +%s)_$$.sh"
    SSH_KEEP_FILE="$keep"
    cat > "$runner" <<EOF
#!/bin/bash
sleep ${secs}
if [ ! -f "${keep}" ]; then
    systemctl revert "${SERVICE_NAME}.socket" >/dev/null 2>&1
    tar xzf "${SSH_LAST_BACKUP}" -C / >/dev/null 2>&1
    systemctl daemon-reload >/dev/null 2>&1
    if systemctl list-unit-files "${SERVICE_NAME}.socket" >/dev/null 2>&1 && systemctl is-active --quiet "${SERVICE_NAME}.socket" 2>/dev/null; then
        systemctl restart "${SERVICE_NAME}.socket" >/dev/null 2>&1
    else
        systemctl restart "${SERVICE_NAME}" >/dev/null 2>&1 || service "${SERVICE_NAME}" restart >/dev/null 2>&1
    fi
fi
rm -f "${keep}" "${runner}"
EOF
    chmod +x "$runner"
    if command -v setsid >/dev/null 2>&1; then
        setsid bash "$runner" >/dev/null 2>&1 </dev/null &
    else
        nohup bash "$runner" >/dev/null 2>&1 </dev/null &
        disown 2>/dev/null
    fi
    echo -e "${RED}━━━━━━━━ 安全回滚已启用 (${secs}s) ━━━━━━━━${NC}"
    echo -e "${YELLOW}请立即${GREEN}另开一个新的 SSH 会话${YELLOW}测试是否仍能登录。${NC}"
    echo -e "能登录 → 执行下面命令${GREEN}取消回滚${NC}(否则 ${secs}s 后自动恢复原配置):"
    echo -e "    ${GREEN}touch ${keep}${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# 成功应用后询问是否启用定时自动回滚 (默认启用)
ssh_offer_autorollback() {
    echo -e "\n${YELLOW}强烈建议启用“定时自动回滚”防止锁死。${NC}"
    if confirm "启用安全回滚保护?"; then
        ssh_arm_autorollback 120
    fi
}

# 兼容旧调用: 等价于安全应用 (不再直接 exit)
restart_service() {
    ssh_safe_apply
}

# ---------- 前置健康检查 / 修复 (改动前先确认 sshd 本身正常) ----------
# 体检: 问题写入 SSH_HEALTH_ISSUES 数组。返回 0=健康 / 1=有问题
ssh_health_check() {
    SSH_HEALTH_ISSUES=()
    local sshd_bin; sshd_bin="$(command -v sshd || echo /usr/sbin/sshd)"

    # 1) 程序是否存在
    if [ ! -x "$sshd_bin" ]; then
        SSH_HEALTH_ISSUES+=("sshd 程序不存在 (可能未安装 openssh-server)")
    else
        # 2) 校验现有配置 (自动区分“运行时问题”与真正的配置语法错误, 并尝试自愈)
        _ssh_config_test
        case $? in
            0) ;;
            2) SSH_HEALTH_ISSUES+=("sshd 运行时环境异常且自动修复失败: $(echo "$SSH_SSHDT_OUT" | head -1)") ;;
            *) SSH_HEALTH_ISSUES+=("现有 sshd 配置语法错误: $(echo "$SSH_SSHDT_OUT" | head -1)") ;;
        esac
    fi

    # 3) 单元是否被 mask
    if command -v systemctl >/dev/null 2>&1; then
        local en_s en_k
        en_s=$(systemctl is-enabled "$SERVICE_NAME" 2>/dev/null)
        en_k=$(systemctl is-enabled "${SERVICE_NAME}.socket" 2>/dev/null)
        [ "$en_s" = "masked" ] && SSH_HEALTH_ISSUES+=("${SERVICE_NAME}.service 被 mask (已屏蔽)")
        [ "$en_k" = "masked" ] && SSH_HEALTH_ISSUES+=("${SERVICE_NAME}.socket 被 mask (已屏蔽)")

        # 3.5) socket 处于 failed: 明确指出常见根因(override 端口重复导致重复绑定)
        if [ "$(systemctl is-failed "${SERVICE_NAME}.socket" 2>/dev/null)" = "failed" ]; then
            local dup_hint=""
            local ovf="/etc/systemd/system/${SERVICE_NAME}.socket.d/override.conf"
            if [ -f "$ovf" ]; then
                local _all _uni
                _all=$(grep -cE '^[[:space:]]*ListenStream=[0-9]+' "$ovf" 2>/dev/null)
                _uni=$(grep -E '^[[:space:]]*ListenStream=[0-9]+' "$ovf" 2>/dev/null | sed 's/.*=//' | sort -u | wc -l)
                [ "${_all:-0}" -gt "${_uni:-0}" ] && dup_hint=" —— override 中存在重复端口, 会重复绑定同一端口(可自动修复)"
            fi
            SSH_HEALTH_ISSUES+=("${SERVICE_NAME}.socket 启动失败 (failed)${dup_hint}")
        fi

        # 4) 运行状态: socket 与 service 任一 active 即正常 (不再二选一误判)
        local mode; mode=$(_ssh_active_mode)
        if [ "$mode" = "none" ]; then
            local st; st=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null)
            case "$st" in
                failed) SSH_HEALTH_ISSUES+=("${SERVICE_NAME}.service 处于 failed 状态") ;;
                "")     SSH_HEALTH_ISSUES+=("无法查询 ${SERVICE_NAME} 状态 (可能无 systemd)") ;;
                *)      SSH_HEALTH_ISSUES+=("SSH 未运行 (${SERVICE_NAME}.service=${st}, ${SERVICE_NAME}.socket 亦未激活)") ;;
            esac
        fi
    fi

    # 5) 是否确实在监听 (按生效端口判定; socket 激活时由 systemd 持有监听)
    if ! _ssh_listening_ok; then
        SSH_HEALTH_ISSUES+=("生效端口($(_ssh_effective_ports)) 均未监听")
    fi

    [ ${#SSH_HEALTH_ISSUES[@]} -eq 0 ]
}

# 尝试修复常见 sshd 异常 (保守: 不盲改配置)
ssh_repair() {
    local sshd_bin; sshd_bin="$(command -v sshd || echo /usr/sbin/sshd)"
    echo -e "${BLUE}正在尝试修复 SSH 服务...${NC}"

    # a) 未安装 -> 安装 openssh-server
    if [ ! -x "$sshd_bin" ]; then
        echo -e "${BLUE}  安装 openssh-server ...${NC}"
        install_package_if_missing sshd openssh-server
        sshd_bin="$(command -v sshd || echo /usr/sbin/sshd)"
    fi

    # b) 解除 mask
    if command -v systemctl >/dev/null 2>&1; then
        [ "$(systemctl is-enabled "$SERVICE_NAME" 2>/dev/null)" = "masked" ] && {
            echo -e "${BLUE}  解除 ${SERVICE_NAME}.service 屏蔽 ...${NC}"; systemctl unmask "$SERVICE_NAME" >/dev/null 2>&1; }
        [ "$(systemctl is-enabled "${SERVICE_NAME}.socket" 2>/dev/null)" = "masked" ] && {
            echo -e "${BLUE}  解除 ${SERVICE_NAME}.socket 屏蔽 ...${NC}"; systemctl unmask "${SERVICE_NAME}.socket" >/dev/null 2>&1; }
    fi

    # b2) socket override 端口重复 -> 重复绑定 -> socket 失败 -> SSH 全挂; 先修这个
    _ssh_fix_socket_override

    # c) 修运行时问题: /run/sshd 缺失、主机密钥缺失 —— 这些都不是配置错误
    _ssh_ensure_runtime_dir

    # d) 复检: 只有确认是“真正的配置语法错误”才提供从备份恢复 (不擅自改写用户配置)
    if [ -x "$sshd_bin" ]; then
        _ssh_config_test
        if [ $? -eq 1 ]; then
            echo -e "${RED}  现有配置语法错误:${NC}"
            echo "$SSH_SSHDT_OUT" | head -5 | sed 's/^/    /'
            local newest
            newest=$(ls -1t /root/.ssh_cmd_backups/ssh_*.tar.gz 2>/dev/null | head -1)
            if [ -n "$newest" ]; then
                echo -e "${YELLOW}  发现历史备份: ${newest}${NC}"
                if confirm "  是否用该备份恢复 sshd 配置?"; then
                    tar xzf "$newest" -C / >/dev/null 2>&1
                    systemctl daemon-reload >/dev/null 2>&1
                    echo -e "${GREEN}  ✓ 已从备份恢复配置${NC}"
                fi
            else
                echo -e "${YELLOW}  无历史备份, 请手动修正 ${SSH_CONF} 后重试。${NC}"
            fi
        fi
    fi

    # e) 启动 SSH: 只操作系统当前实际采用的方式, 绝不同时拉起 socket 和 service
    #    (两者都监听同一端口会互相冲突, 反而可能把本来正常的环境弄坏)
    if command -v systemctl >/dev/null 2>&1 && [ -x "$sshd_bin" ] && _ssh_config_test >/dev/null 2>&1; then
        local mode; mode=$(_ssh_active_mode)
        if [ "$mode" = "socket" ]; then
            echo -e "${BLUE}  当前为 socket 激活模式, 重启 ${SERVICE_NAME}.socket ...${NC}"
            systemctl restart "${SERVICE_NAME}.socket" >/dev/null 2>&1
        elif [ "$mode" = "service" ]; then
            echo -e "${BLUE}  当前为传统 service 模式, 重启 ${SERVICE_NAME} ...${NC}"
            systemctl restart "$SERVICE_NAME" >/dev/null 2>&1
        else
            # 两者都没起: 按发行版默认方式拉起 —— socket 单元已 enabled 才用 socket, 否则用 service
            local en_k; en_k=$(systemctl is-enabled "${SERVICE_NAME}.socket" 2>/dev/null)
            if [ "$en_k" = "enabled" ]; then
                echo -e "${BLUE}  ${SERVICE_NAME}.socket 已启用但未运行, 正在启动 ...${NC}"
                systemctl start "${SERVICE_NAME}.socket" >/dev/null 2>&1
            else
                echo -e "${BLUE}  正在启用并启动 ${SERVICE_NAME} ...${NC}"
                systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
                systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || service "$SERVICE_NAME" restart >/dev/null 2>&1
            fi
        fi
        systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1

        # f) 兜底: 若 socket 仍处于 failed, 提议丢弃本脚本写的 override 回到系统默认端口
        sleep 1
        if [ "$(systemctl is-failed "${SERVICE_NAME}.socket" 2>/dev/null)" = "failed" ] \
            && [ -f "/etc/systemd/system/${SERVICE_NAME}.socket.d/override.conf" ]; then
            echo -e "${RED}  ${SERVICE_NAME}.socket 仍然启动失败。${NC}"
            echo -e "${YELLOW}  可丢弃本脚本写入的端口覆盖(systemctl revert), 回到系统默认端口以先恢复 SSH。${NC}"
            if confirm "  是否丢弃端口覆盖并恢复默认?"; then
                systemctl revert "${SERVICE_NAME}.socket" >/dev/null 2>&1
                systemctl daemon-reload >/dev/null 2>&1
                systemctl reset-failed "${SERVICE_NAME}.socket" "$SERVICE_NAME" >/dev/null 2>&1
                systemctl start "${SERVICE_NAME}.socket" >/dev/null 2>&1
                if systemctl is-active --quiet "${SERVICE_NAME}.socket" 2>/dev/null; then
                    echo -e "${GREEN}  ✓ 已恢复默认端口, ${SERVICE_NAME}.socket 已启动${NC}"
                fi
            fi
        fi
    fi
    sleep 1
}

# 故障诊断: 修复失败时输出真实原因(单元状态 + 日志 + 监听情况), 而不是只说“仍有问题”
ssh_show_diagnostics() {
    panel_top "SSH 故障诊断"
    if command -v systemctl >/dev/null 2>&1; then
        echo -e "${YELLOW}单元状态:${NC}"
        printf '  %-16s enabled=%-10s active=%s\n' "${SERVICE_NAME}.service" \
            "$(systemctl is-enabled "$SERVICE_NAME" 2>&1 | head -1)" "$(systemctl is-active "$SERVICE_NAME" 2>&1 | head -1)"
        printf '  %-16s enabled=%-10s active=%s\n' "${SERVICE_NAME}.socket" \
            "$(systemctl is-enabled "${SERVICE_NAME}.socket" 2>&1 | head -1)" "$(systemctl is-active "${SERVICE_NAME}.socket" 2>&1 | head -1)"
        echo -e "${YELLOW}启动失败原因 (systemctl status):${NC}"
        systemctl status "$SERVICE_NAME" --no-pager -l 2>/dev/null | tail -12 | sed 's/^/  /'
        if command -v journalctl >/dev/null 2>&1; then
            echo -e "${YELLOW}最近日志 (${SERVICE_NAME}):${NC}"
            journalctl -u "$SERVICE_NAME" --no-pager -n 15 2>/dev/null | tail -15 | sed 's/^/  /'
            echo -e "${YELLOW}最近日志 (${SERVICE_NAME}.socket):${NC}"
            journalctl -u "${SERVICE_NAME}.socket" --no-pager -n 8 2>/dev/null | tail -8 | sed 's/^/  /'
        fi
    fi
    echo -e "${YELLOW}生效端口:${NC} $(_ssh_effective_ports)"
    echo -e "${YELLOW}当前 TCP 监听:${NC}"
    ss -ltnp 2>/dev/null | head -12 | sed 's/^/  /'
    panel_bot
    echo -e "${YELLOW}可手动尝试: ${GREEN}systemctl start ${SERVICE_NAME}.socket${YELLOW} 或 ${GREEN}systemctl start ${SERVICE_NAME}${NC}"
}

# 前置守卫: 体检 -> (可选)修复 -> 复检。返回 0=可继续 / 1=中止
ssh_preflight() {
    detect_os
    if ssh_health_check; then
        echo -e "${GREEN}✓ SSH 服务体检正常, 继续操作。${NC}"
        return 0
    fi

    panel_top "SSH 服务体检: 发现异常"
    local i
    for i in "${SSH_HEALTH_ISSUES[@]}"; do echo -e "  ${RED}✗${NC} $i"; done
    panel_bot
    echo -e "${YELLOW}在 sshd 本身异常时改配置, 失败原因会难以定位, 且可能导致无法登录。${NC}"
    if ! confirm "是否先尝试自动修复?"; then
        if confirm "${RED}不修复并继续有风险, 确认继续?${NC}"; then
            return 0
        else
            echo -e "${YELLOW}已取消操作。${NC}"; return 1
        fi
    fi

    ssh_repair
    if ssh_health_check; then
        echo -e "${GREEN}✓ 修复成功, SSH 服务恢复正常, 继续操作。${NC}"
        return 0
    fi

    echo -e "${RED}修复后仍存在问题:${NC}"
    for i in "${SSH_HEALTH_ISSUES[@]}"; do echo -e "  ${RED}✗${NC} $i"; done
    # 输出真实原因, 便于定位(而不是只说“仍有问题”)
    ssh_show_diagnostics
    if confirm "${RED}仍要继续操作吗?${NC}"; then
        return 0
    else
        echo -e "${YELLOW}已取消操作, 请先修复 SSH 服务。${NC}"; return 1
    fi
}

# --- 4. 功能：启用密钥登录 ---
enable_key_login() {
    echo -e "\n${YELLOW}[操作] 正在配置 Root 密钥登录...${NC}"
    # 前置: sshd 服务本身异常时先修复, 避免误判与锁死
    ssh_preflight || return 1
    mkdir -p /root/.ssh && chmod 700 /root/.ssh

    # 检查是否存在云平台的root登录限制
    if [ -f "$AUTH_KEYS" ] && grep -q 'command=".*Please login as the user.*rather than.*root' "$AUTH_KEYS"; then
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${RED}检测到云平台的 root 登录限制！${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}当前 authorized_keys 包含阻止 root 登录的命令${NC}"
        echo -e "${BLUE}示例: command=\"echo 'Please login...'\"${NC}"
        echo ""
        if confirm "是否清理此限制以允许 root 登录？"; then
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
        confirm "是否添加新的密钥对？" && need_new_key=true
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

    # 配置 SSH (改动前先备份, 失败可自动回滚)
    echo -e "${BLUE}配置 SSH 服务...${NC}"
    ssh_backup
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
        if confirm "是否禁用密码登录？"; then
            if [ ! -s "$AUTH_KEYS" ] || ! grep -qE '^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp[0-9]+|ssh-dss|sk-ssh|sk-ecdsa)' "$AUTH_KEYS"; then
                echo -e "${RED}authorized_keys 中未发现有效公钥, 为避免锁死, 已拒绝禁用密码登录!${NC}"
                echo -e "${YELLOW}请先确认密钥登录可用, 再来禁用密码。${NC}"
            else
                set_ssh_config "PasswordAuthentication" "no"
                echo -e "${GREEN}已禁用密码登录${NC}"
            fi
        else
            echo -e "${YELLOW}已保留密码登录${NC}"
        fi
    fi
    
    # 显示当前 authorized_keys 内容（仅显示前几个字符）
    echo -e "\n${BLUE}当前 authorized_keys 内容:${NC}"
    if [ -f "$AUTH_KEYS" ]; then
        awk '{print NR". " substr($1,1,20)"... " substr($2,1,30)"... " $3}' "$AUTH_KEYS"
    fi
    
    if ssh_safe_apply; then
        ssh_offer_autorollback
    else
        echo -e "${RED}SSH 配置应用失败, 已回滚到改动前状态, 未做更改。${NC}"
        return 1
    fi

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
    # 前置: sshd 服务本身异常时先修复, 避免误判与锁死
    ssh_preflight || return 1
    read -p "请输入新端口号 (1-65535): " new_port
    [[ ! "$new_port" =~ ^[0-9]+$ ]] && echo "无效输入" && return
    if [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        echo -e "${RED}端口号超出范围，请输入 1-65535 之间的值${NC}"
        return
    fi

    echo -e "${YELLOW}模式说明: [A]追加=保留 22 端口(更安全, 推荐); [R]替换=仅监听新端口。${NC}"
    echo -e "${RED}注意: 云服务器请先在“安全组/防火墙”放行新端口 ${new_port}, 否则可能连不上!${NC}"
    read -p "模式: [A]追加(保留22, 默认) | [R]替换(仅新端口): " p_mode
    [ -z "$p_mode" ] && p_mode="A"

    # 改动前备份, 便于失败/锁死时回滚
    ssh_backup

    # 修改配置逻辑
    if [[ "$p_mode" =~ ^[Aa]$ ]]; then
        sed -i 's/^#Port 22/Port 22/' "$SSH_CONF"
        grep -q "^Port 22" "$SSH_CONF" || echo "Port 22" >> "$SSH_CONF"
        grep -q "^Port $new_port" "$SSH_CONF" || sed -i "/^Port 22/a Port $new_port" "$SSH_CONF"
    else
        sed -i "s/^#\?Port.*/Port $new_port/" "$SSH_CONF"
    fi

    configure_ssh_socket_ports "$p_mode" "$new_port"

    # A. 处理防火墙 (重启前先放行新端口; 复用 common 的通用放行)
    open_firewall "$new_port" tcp

    # B. 处理 SELinux (关键步骤)
    if [[ "$SELINUX_STATE" == "Enforcing" ]]; then
        echo "检测到 SELinux 开启，正在尝试添加端口策略..."
        if command -v semanage >/dev/null; then
            semanage port -a -t ssh_port_t -p tcp "$new_port" 2>/dev/null \
                || semanage port -m -t ssh_port_t -p tcp "$new_port" 2>/dev/null
        else
            echo -e "${RED}警告: 未找到 semanage 命令，请手动安装 policycoreutils-python(-utils) 以支持 SELinux 端口修改${NC}"
        fi
    fi

    # 校验 + 重启 + 服务存活验证 (失败自动回滚)
    if ! ssh_safe_apply; then
        echo -e "${RED}端口修改失败, 已回滚到原配置。${NC}"
        return 1
    fi

    # 验证新端口: (1) 本机监听  (2) 本机 TCP 自连测试
    sleep 1
    local listen_ok=1 tcp_ok=1
    if command -v ss >/dev/null 2>&1; then
        ss -ltn "sport = :${new_port}" 2>/dev/null | grep -q "LISTEN" || listen_ok=0
    else
        listen_ok=2   # 无 ss, 无法判定
    fi
    if _ssh_tcp_check "$new_port"; then tcp_ok=1; else tcp_ok=0; fi

    case "$listen_ok" in
        1) echo -e "${GREEN}✓ 端口监听检测: ${new_port} 已在监听${NC}" ;;
        0) echo -e "${RED}⚠ 端口监听检测: 未发现 ${new_port} 在监听${NC}" ;;
        2) echo -e "${YELLOW}· 端口监听检测: 缺少 ss, 跳过${NC}" ;;
    esac
    if [ "$tcp_ok" = 1 ]; then
        echo -e "${GREEN}✓ 本机 TCP 自连: 成功连上 ${new_port}${NC}"
    else
        echo -e "${RED}⚠ 本机 TCP 自连: 无法连上 ${new_port} (sshd 未接受/本地防火墙/端口未真正生效)${NC}"
    fi

    # 监听为“确定未监听”, 或 TCP 自连失败 → 判定端口不可用, 提示回滚
    if [ "$listen_ok" = 0 ] || [ "$tcp_ok" = 0 ]; then
        echo -e "${RED}新端口 ${new_port} 本机自检未通过, 可能无法用它登录!${NC}"
        if confirm "是否立即回滚到原配置?"; then
            ssh_restore
            return 1
        fi
    fi

    echo -e "${YELLOW}提示: 本机自连仅验证本地可达; 云服务器仍需在${GREEN}安全组/外部防火墙${YELLOW}放行 ${new_port}。${NC}"
    echo -e "${YELLOW}请务必${GREEN}另开新会话用新端口测试${YELLOW}: ${GREEN}ssh -p ${new_port} <用户>@<服务器IP>${NC}"
    ssh_offer_autorollback
}
