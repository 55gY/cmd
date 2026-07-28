#!/bin/bash
# ============================================================
# install.sh  —  系统管理脚本 (入口 / 加载器 / 主菜单)
#
# 设计:
#   - 共用依赖 lib/common.sh 随本脚本一起加载, 内含全部功能的“状态检测”,
#     因此一进入主菜单即可显示所有功能状态, 无需下载任何功能模块。
#   - 各功能实现在 modules/*.sh, 按需加载: 仅当用户在菜单中选择该功能时,
#     才从本地(或仓库)加载对应模块, 不会一次性下载全部。
#
# 运行方式(两者皆可):
#   1) 本地: git clone 后  ./install.sh   (按相对路径加载 lib 与 modules)
#   2) 一键: bash <(curl -Ls .../install.sh)  (自动从仓库按需下载依赖/模块)
# ============================================================

# 仓库 raw 根地址 (可用环境变量 CMD_REPO_BASE 覆盖)
REPO_RAW_BASE="${CMD_REPO_BASE:-https://raw.githubusercontent.com/55gY/cmd/main}"

# ---------- 定位依赖: 本地目录 或 远程会话临时目录 ----------
_self="${BASH_SOURCE[0]:-$0}"
_self_dir=""
if [[ -n "$_self" && "$_self" != "bash" && "$_self" != "-bash" ]]; then
    _self_dir="$(cd "$(dirname "$_self")" 2>/dev/null && pwd)"
fi

if [[ -n "$_self_dir" && -f "$_self_dir/lib/common.sh" ]]; then
    # 本地模式: 与 install.sh 同目录已存在 lib/ 与 modules/
    BASE_DIR="$_self_dir"
    REMOTE=0
else
    # 远程模式: 下载到本次会话的临时目录, 退出时清理
    BASE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cmd.XXXXXX")"
    REMOTE=1
    mkdir -p "$BASE_DIR/lib" "$BASE_DIR/modules"
    trap '[[ "$REMOTE" -eq 1 && -n "$BASE_DIR" ]] && rm -rf "$BASE_DIR"' EXIT
fi

# ---------- 依赖/模块获取: 本地存在则直接用, 否则下载 ----------
fetch_file() {
    local rel="$1"
    local dest="$BASE_DIR/$rel"
    [[ -f "$dest" ]] && return 0
    mkdir -p "$(dirname "$dest")"
    local url="$REPO_RAW_BASE/$rel"
    if command -v curl >/dev/null 2>&1 && curl -fsSL "$url" -o "$dest" 2>/dev/null; then
        return 0
    fi
    if command -v wget >/dev/null 2>&1 && wget -qO "$dest" "$url" 2>/dev/null; then
        return 0
    fi
    echo "依赖下载失败: $url (请确认网络或已安装 curl/wget)" >&2
    return 1
}

# 加载共用依赖 (含全部功能的状态检测)
load_common() {
    fetch_file "lib/common.sh" || { echo "无法加载 lib/common.sh, 退出。" >&2; exit 1; }
    # shellcheck source=/dev/null
    source "$BASE_DIR/lib/common.sh"
}

# 按需加载功能模块 (同一会话仅加载一次)
load_module() {
    local name="$1"
    local guard="_LOADED_${name}"
    [[ -n "${!guard:-}" ]] && return 0
    if ! fetch_file "modules/${name}.sh"; then
        echo "模块 ${name} 加载失败。" >&2
        return 1
    fi
    # shellcheck source=/dev/null
    source "$BASE_DIR/modules/${name}.sh" || return 1
    printf -v "$guard" '%s' 1
}

# ---------- 启动: 先加载共用依赖 ----------
load_common

# ---------- 命令行参数 (非交互) ----------
# 用法: install.sh ss config | ss auto | reality config | reality auto
if [[ "$1" == "ss" && "$2" == "config" ]]; then
    detect_os
    load_module ss && view_ss_config false
    exit $?
elif [[ "$1" == "ss" && "$2" == "auto" ]]; then
    check_root
    detect_os
    load_module ss && install_ss false true   # 不显示二维码, 自动确认(非交互)
    exit $?
elif [[ "$1" == "reality" && "$2" == "config" ]]; then
    detect_os
    load_module reality && reality_show_config false   # 不含二维码
    exit $?
elif [[ "$1" == "reality" && "$2" == "auto" ]]; then
    check_root
    detect_os
    load_module reality && reality_install auto        # 随机全新节点, 非交互
    exit $?
fi

# ---------- 主程序循环 ----------
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
    echo "8. Reality (VLESS) 管理"
    echo "0. 退出"
    read -p "选择操作: " opt
    case $opt in
        1) load_module ss     && ss_menu ;;
        2) load_module bbr    && { bbr_status_panel; enable_bbr; read -n 1 -p "按任意键继续..."; } ;;
        3) load_module ssh    && { ssh_status_panel; enable_key_login; read -n 1 -p "按任意键继续..."; } ;;
        4) load_module ssh    && { ssh_status_panel; change_port; read -n 1 -p "按任意键继续..."; } ;;
        5) load_module system && { system_status_panel; change_timezone; read -n 1 -p "按任意键继续..."; } ;;
        6) load_module system && { system_status_panel; install_chinese_support; read -n 1 -p "按任意键继续..."; } ;;
        7) load_module mihomo && mihomo_menu ;;
        8) load_module reality && reality_menu ;;
        0) exit 0 ;;
        *) echo "无效选项" ;;
    esac
done
