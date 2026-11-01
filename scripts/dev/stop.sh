#!/usr/bin/env bash
# 停止 `make dev` 起的后台进程（gateway / agent / mock-llm）。
#
# 为什么不写成 `kill $(cat .tmp/agent.pid)`：
#   pid 文件可能**丢失**（被上次 stop 自己 rm、被 make clean 清掉、克隆副本里本来就没有），
#   也可能**过期**（进程早退出了，PID 被系统复用给别的程序）。只信 pid 文件会两头出错：
#     漏杀 → 孤儿进程占着 8080/4433，下一次 `make dev` 起不来，且 `make stop` 说"没在运行"；
#     错杀 → 过期 PID 正好撞上别人的进程，一 kill 就是事故。
# 所以这里对每个候选 PID 做两道核对：**cwd 必须是本仓库根**、**可执行文件必须是
# target/debug/<bin>**。核对不过就不动它（宁可漏杀，不可错杀），并把原因打出来。
#
# 只发 SIGTERM（agent 有优雅关闭分支），等 5s 仍未退就提示手工 kill -9，不自动升级。

set -u

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
PID_DIR="$REPO_ROOT/.tmp"
PROCS=(gateway agent mock-llm)
WAIT_TENTHS=50 # 50 × 0.1s = 5s

# 进程的 cwd：Linux 读 /proc，macOS 用 lsof。
proc_cwd() {
    if [ -e "/proc/$1/cwd" ]; then
        readlink "/proc/$1/cwd" 2>/dev/null
        return
    fi
    lsof -a -p "$1" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -n 1
}

# 进程的可执行文件路径。二进制被删（target/ 被清但进程还在跑）时仍会打印**原路径**
# （Linux 带 " (deleted)" 后缀），正好用来识别这种幽灵进程。
proc_exe() {
    if [ -e "/proc/$1/exe" ]; then
        readlink "/proc/$1/exe" 2>/dev/null
        return
    fi
    lsof -a -p "$1" -d txt -Fn 2>/dev/null | sed -n 's/^n//p' | head -n 1
}

stopped=0
skipped=0
remaining=0

for name in "${PROCS[@]}"; do
    pid_file="$PID_DIR/$name.pid"
    # 候选来源：pid 文件（正常路径）+ 命令行匹配（兜底，覆盖 pid 文件丢失的孤儿）。
    # 命令行是相对路径 `target/debug/agent`，所以同一个 pattern 可能命中别的仓库，靠下面的
    # cwd / exe 核对挡掉。
    pids="$(
        {
            [ -f "$pid_file" ] && tr -dc '0-9' <"$pid_file"
            echo
            pgrep -f "target/debug/${name}([[:space:]]|\$)" 2>/dev/null
        } | sort -u
    )"

    for pid in $pids; do
        case "$pid" in '' | *[!0-9]*) continue ;; esac
        kill -0 "$pid" 2>/dev/null || continue # 已退出（过期 pid 文件）

        cwd="$(proc_cwd "$pid")"
        exe="$(proc_exe "$pid")"
        exe="${exe% (deleted)}"

        if [ -z "$cwd" ] || [ -z "$exe" ]; then
            echo "  ! $name pid=$pid 忽略：读不到 cwd/exe，无法确认归属（手工确认：ps -p $pid -o command=）"
            skipped=$((skipped + 1))
            continue
        fi
        if [ "$cwd" != "$REPO_ROOT" ]; then
            echo "  ! $name pid=$pid 忽略：cwd=${cwd}，不是本仓库"
            skipped=$((skipped + 1))
            continue
        fi
        if [ "$exe" != "$REPO_ROOT/target/debug/$name" ]; then
            echo "  ! $name pid=$pid 忽略：exe=${exe}，不是 target/debug/$name"
            skipped=$((skipped + 1))
            continue
        fi

        if ! kill -TERM "$pid" 2>/dev/null; then
            echo "  ! $name pid=${pid}：SIGTERM 发送失败（权限？）"
            skipped=$((skipped + 1))
            continue
        fi

        i=0
        while [ "$i" -lt "$WAIT_TENTHS" ] && kill -0 "$pid" 2>/dev/null; do
            sleep 0.1
            i=$((i + 1))
        done

        if kill -0 "$pid" 2>/dev/null; then
            echo "  … $name pid=$pid 已收 SIGTERM，5s 后仍在退出中（pid 文件保留，重试 stop 即可；卡住就 kill -9 $pid）"
            remaining=$((remaining + 1))
        else
            echo "✔ 已停止 $name (pid=$pid)"
            stopped=$((stopped + 1))
            rm -f "$pid_file"
        fi
    done

    # pid 文件收尾：进程已退出（过期），或指向的压根不是我们的二进制（损坏 / PID 复用）
    # → 都删掉，免得下次把假信息当真。只有"确实是我们的进程但还没退"时才保留。
    if [ -f "$pid_file" ]; then
        pid="$(tr -dc '0-9' <"$pid_file")"
        if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
            rm -f "$pid_file"
        else
            exe="$(proc_exe "$pid")"
            if [ "${exe% (deleted)}" != "$REPO_ROOT/target/debug/$name" ]; then
                rm -f "$pid_file"
            fi
        fi
    fi
done

if [ "$stopped" -eq 0 ] && [ "$remaining" -eq 0 ]; then
    echo "  没有在运行的本仓库 dev 进程（gateway / agent / mock-llm）"
fi
if [ "$skipped" -gt 0 ]; then
    echo "  有 $skipped 个候选未处理（见上面的忽略原因）；全量核对：pgrep -lf 'target/debug'"
fi

# 端口仍被占但已经没有归属进程时，给一条明确的下一步，而不是让人对着 curl 超时猜。
for port in 8080 4433; do
    holder="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR==2 {print $1" pid="$2}')"
    [ -n "$holder" ] && echo "  ! 端口 $port 仍被占用：${holder}（不是本脚本管理的进程，需自行确认）"
done

exit 0
