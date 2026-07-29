#!/bin/bash
# modules/system.sh — 系统配置 (时区 / 中文字体+Locale). 依赖 lib/common.sh

# 系统配置 状态检测面板 (统一样式)
system_status_panel() {
    detect_os
    local cur_locale font_status="未知"
    cur_locale=$(locale 2>/dev/null | grep "^LANG=" | cut -d= -f2)
    [ -z "$cur_locale" ] && cur_locale="未设置"
    if command -v fc-list >/dev/null 2>&1; then
        if fc-list 2>/dev/null | grep -qi "wqy"; then font_status="已安装 (WQY)"; else font_status="未安装"; fi
    fi
    panel_top "系统配置 状态检测"
    echo -e "系统时区         : ${CYAN}${CURRENT_TIMEZONE}${NC}"
    if locale -a 2>/dev/null | grep -qi "zh_CN"; then
        echo -e "中文 Locale      : ${GREEN_BOLD}已生成 zh_CN${NC}"
    else
        echo -e "中文 Locale      : ${RED_BOLD}未生成${NC}"
    fi
    echo -e "当前 LANG        : ${CYAN}${cur_locale}${NC}"
    echo -e "中文字体 (WQY)   : ${CYAN}${font_status}${NC}"
    panel_bot
}

change_timezone() {
    echo -e "\n${YELLOW}[操作] 修改系统时区为 Asia/Shanghai...${NC}"
    echo -e "当前时区: ${BLUE}$CURRENT_TIMEZONE${NC}"
    
    if [[ "$CURRENT_TIMEZONE" == "Asia/Shanghai" ]]; then
        echo -e "${GREEN}时区已经是 Asia/Shanghai，无需修改。${NC}"
        return
    fi
    
    if ! confirm "确认将时区修改为 Asia/Shanghai？"; then
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
