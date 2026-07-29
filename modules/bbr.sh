#!/bin/bash
# modules/bbr.sh — BBR 网络加速 + 系统优化. 依赖 lib/common.sh

# BBR / 网络优化 状态检测面板 (统一样式)
bbr_status_panel() {
    detect_os
    local cc qdisc
    cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    panel_top "BBR / 网络优化 状态检测"
    if [[ "$BBR_STATUS" == "已启用" ]]; then
        echo -e "BBR 加速         : ${GREEN_BOLD}已启用${NC}"
    else
        echo -e "BBR 加速         : ${RED_BOLD}未启用${NC}"
    fi
    echo -e "内核版本         : ${CYAN}$(uname -r)${NC}"
    echo -e "拥塞控制算法     : ${CYAN}${cc:-未知}${NC}"
    echo -e "默认队列算法     : ${CYAN}${qdisc:-未知}${NC}"
    if grep -q 'tcp_congestion_control[[:space:]]*=[[:space:]]*bbr' /etc/sysctl.conf 2>/dev/null; then
        echo -e "持久化配置       : ${GREEN_BOLD}已写入 /etc/sysctl.conf${NC}"
    else
        echo -e "持久化配置       : ${RED_BOLD}未写入${NC}"
    fi
    echo -e "虚拟化环境       : ${CYAN}${VIRT_TYPE:-none}${NC}"
    panel_bot
}

# 精准还原: 只移除本脚本写入的配置(标记块 + 旧版无标记的同值行), 不动他人配置
bbr_revert() {
    check_root
    panel_top "还原 BBR / 网络优化 配置"
    echo -e "将${GREEN}只移除本脚本写入的内容${NC}, 文件中其它程序/你自己的配置${GREEN}保持不变${NC}。"
    panel_bot
    confirm "确认还原?" || { echo -e "${YELLOW}已取消${NC}"; return 0; }

    # 1) 移除标记块
    config_block_remove bbr-core   /etc/sysctl.conf
    config_block_remove bbr-opt    /etc/sysctl.conf
    config_block_remove bbr-limits /etc/security/limits.conf

    # 2) 兼容旧版本(无标记)残留: 仅删除与本脚本写入值完全一致的行
    config_line_remove /etc/sysctl.conf \
        "net.core.default_qdisc = fq" \
        "net.ipv4.tcp_congestion_control = bbr"
    config_line_remove /etc/security/limits.conf \
        "*               soft    nofile          1000000" \
        "*               hard    nofile          1000000"

    # 3) 本脚本独占创建的文件, 直接删除
    rm -f /etc/sysctl.d/99-bbr.conf /etc/modules-load.d/bbr.conf

    sysctl --system >/dev/null 2>&1 || sysctl -p >/dev/null 2>&1
    echo -e "${GREEN}✓ 已还原(移除本脚本写入的 BBR/优化配置)。${NC}"
    echo -e "${YELLOW}提示: 拥塞控制算法将在重启后回到系统默认; 当前值: ${CYAN}$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)${NC}"
}

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
    # 只写入本项目的标记块(追加在文件末尾, sysctl 后者生效),
    # 不再全局删除 net.core.default_qdisc / tcp_congestion_control 行 ——
    # 那些行可能是其它程序或用户自己写的, 删除会破坏环境。
    config_block_write bbr-core /etc/sysctl.conf "net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr"
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
    
    # 以标记块方式写入优化参数: 只影响本项目写入的内容, 不动文件里其它程序的配置;
    # 还原时用 config_block_remove 精准移除该块, 无需(也不应)整文件覆盖。
    config_block_write bbr-opt /etc/sysctl.conf "# 系统网络优化 (由脚本写入)
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
#net.ipv4.ip_forward = 1"

    # 配置文件描述符限制 (同样使用标记块, 便于精准还原)
    if [ -f /etc/security/limits.conf ]; then
        config_block_write bbr-limits /etc/security/limits.conf "# 文件描述符限制 (由脚本写入)
*               soft    nofile          1000000
*               hard    nofile          1000000"
        echo -e "${GREEN}✓ 已配置文件描述符限制${NC}"
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
        echo ""
        if confirm "是否继续应用系统网络优化配置？"; then
            add_system_optimization
        fi
        return 0
    fi
    
    echo -e "${YELLOW}当前 BBR 状态: 未启用${NC}"
    echo -e "当前内核版本: ${YELLOW}$(uname -r)${NC}\n"
    
    # 2. 检查内核版本
    if check_kernel_version; then
        echo -e "${GREEN}✓ 内核版本满足要求（≥4.9），可直接启用 BBR${NC}\n"
        
        if ! confirm "是否立即启用 BBR 并应用系统优化？"; then
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
    
    if ! confirm "确认要升级内核并启用 BBR？"; then
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
    
    if confirm "是否立即重启系统？"; then
        echo -e "${GREEN}系统将在 3 秒后重启...${NC}"
        sleep 3
        reboot
    else
        echo -e "${YELLOW}已取消重启，请稍后手动执行 reboot 命令${NC}"
        echo -e "${YELLOW}重启后执行 sysctl net.ipv4.tcp_congestion_control 验证 BBR 状态${NC}"
    fi
}

# BBR 网络优化 管理子菜单 (统一样式: 面板 + 选项)
bbr_menu() {
    local choice
    while true; do
        clear
        bbr_status_panel
        echo "1. 启用 BBR / 应用系统网络优化"
        echo "2. 还原配置 (只移除本脚本写入的内容)"
        echo "0. 返回主菜单"
        read -p "请输入选项: " choice
        case "$choice" in
            1) enable_bbr; read -n 1 -p "按任意键返回 BBR 菜单..." _ ;;
            2) bbr_revert; read -n 1 -p "按任意键返回 BBR 菜单..." _ ;;
            0) break ;;
            *) echo "无效选项"; sleep 1 ;;
        esac
    done
}
