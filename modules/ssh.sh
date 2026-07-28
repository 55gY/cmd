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
    local sshd_bin; sshd_bin="$(command -v sshd || echo /usr/sbin/sshd)"
    echo -e "${BLUE}正在校验 SSH 配置 (sshd -t)...${NC}"
    if ! "$sshd_bin" -t 2>/tmp/_sshd_test.$$; then
        echo -e "${RED}配置语法校验失败:${NC}"
        cat /tmp/_sshd_test.$$ 2>/dev/null
        rm -f /tmp/_sshd_test.$$
        ssh_restore
        return 1
    fi
    rm -f /tmp/_sshd_test.$$
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
    read -p "启用安全回滚保护? [Y/n]: " _arm
    if [[ ! "$_arm" =~ ^[Nn]$ ]]; then
        ssh_arm_autorollback 120
    fi
}

# 兼容旧调用: 等价于安全应用 (不再直接 exit)
restart_service() {
    ssh_safe_apply
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
        read -p "是否禁用密码登录？(y/n): " dis_pwd
        
        if [[ "$dis_pwd" =~ ^[Yy]$ ]]; then
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
        read -p "是否立即回滚到原配置? [Y/n]: " _rb
        if [[ ! "$_rb" =~ ^[Nn]$ ]]; then
            ssh_restore
            return 1
        fi
    fi

    echo -e "${YELLOW}提示: 本机自连仅验证本地可达; 云服务器仍需在${GREEN}安全组/外部防火墙${YELLOW}放行 ${new_port}。${NC}"
    echo -e "${YELLOW}请务必${GREEN}另开新会话用新端口测试${YELLOW}: ${GREEN}ssh -p ${new_port} <用户>@<服务器IP>${NC}"
    ssh_offer_autorollback
}
