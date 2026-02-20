#!/usr/bin/env bash
set -euo pipefail

# SDN DoS Guard helper script for Ubuntu
# Actions: install | start | stop | status | mininet | ryu | web | logs | help

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RUN_DIR="${PROJECT_ROOT}/.run"
LOG_DIR="${PROJECT_ROOT}/logs"
VENV_DIR="${PROJECT_ROOT}/.venv"
PYTHON="python3"
export PYTHONPATH="${PROJECT_ROOT}:${PYTHONPATH:-}"

mkdir -p "${RUN_DIR}" "${LOG_DIR}"

ensure_writable_state() {
  local owner_uid owner_gid
  owner_uid="$(stat -c %u "${PROJECT_ROOT}" 2>/dev/null || echo "$(id -u)")"
  owner_gid="$(stat -c %g "${PROJECT_ROOT}" 2>/dev/null || echo "$(id -g)")"

  local need_fix
  need_fix="0"
  if [[ ! -w "${RUN_DIR}" || ! -w "${LOG_DIR}" ]]; then
    need_fix="1"
  fi
  if [[ "${need_fix}" = "0" ]]; then
    if find "${RUN_DIR}" "${LOG_DIR}" -maxdepth 1 -type f ! -w -print -quit 2>/dev/null | grep -q .; then
      need_fix="1"
    fi
  fi

  if [[ "${need_fix}" = "1" ]]; then
    sudo chown -R "${owner_uid}":"${owner_gid}" "${RUN_DIR}" "${LOG_DIR}" 2>/dev/null || true
    sudo chmod -R u+rwX "${RUN_DIR}" "${LOG_DIR}" 2>/dev/null || true
  fi
}

safe_kill_pidfile() {
  local f="$1"
  if [[ -f "${f}" ]]; then
    local pid
    pid="$(cat "${f}" 2>/dev/null || true)"
    if [[ -n "${pid}" ]]; then
      kill "${pid}" 2>/dev/null || sudo kill "${pid}" 2>/dev/null || true
    fi
    rm -f "${f}" 2>/dev/null || sudo rm -f "${f}" 2>/dev/null || true
  fi
}

warn_if_root() {
  if [[ "$(id -u)" = "0" ]]; then
    echo "[!] Note: running as root. This is supported, but prefer running as 'ubuntu' to avoid permission issues." >&2
  fi
}

# Load helper libraries
# shellcheck source=scripts/lib/log_manager.sh
if [[ -f "${SCRIPT_DIR}/lib/log_manager.sh" ]]; then
  source "${SCRIPT_DIR}/lib/log_manager.sh"
fi

# shellcheck source=scripts/lib/tunnel_manager.sh
if [[ -f "${SCRIPT_DIR}/lib/tunnel_manager.sh" ]]; then
  source "${SCRIPT_DIR}/lib/tunnel_manager.sh"
fi

# shellcheck source=scripts/lib/env_installer.sh
if [[ -f "${SCRIPT_DIR}/lib/env_installer.sh" ]]; then
  source "${SCRIPT_DIR}/lib/env_installer.sh"
fi

# shellcheck source=scripts/lib/service_manager.sh
if [[ -f "${SCRIPT_DIR}/lib/service_manager.sh" ]]; then
  source "${SCRIPT_DIR}/lib/service_manager.sh"
fi

usage() {
  cat <<EOF
Usage: $(basename "$0") <command>

Commands:
  install        Install system deps and python packages
  up [IP PORT HOSTS]      Install deps, start Ryu/Web, then run Mininet (sudo)
  ryu            Start ryu-manager in background
  web            Start Flask webapp in background
  start          Start both Ryu and Web
  stop           Stop Ryu/Web and clean Mininet
  status         Show running processes
  mininet [IP PORT HOSTS]  Run Mininet lab (sudo)
  logs           Show last logs
  rotate-logs    Rotate logs exceeding threshold (copytruncate)
  clean-logs [--dry-run|-n] [--force|-f] Clean backup log files
  clean-pcaps [--dry-run|-n] [--force|-f] Clean ephemeral unpinned PCAPs
  help           Show this message

Examples:
  ./scripts/sdn_lab.sh install
  ./scripts/sdn_lab.sh start
  ./scripts/sdn_lab.sh mininet 127.0.0.1 6653 4
  ./scripts/sdn_lab.sh rotate-logs
  ./scripts/sdn_lab.sh clean-logs --dry-run
  ./scripts/sdn_lab.sh clean-pcaps --dry-run
  ./scripts/sdn_lab.sh status
  ./scripts/sdn_lab.sh stop
EOF
}

main() {
  cd "${PROJECT_ROOT}"
  warn_if_root
  ensure_writable_state
  case "${1:-help}" in
    install) install_pkgs; pip_install; touch "${RUN_DIR}/installed.flag" ;;
    up) shift || true; up_all "${1:-127.0.0.1}" "${2:-6653}" "${3:-4}" "${@:4}" ;;
    ryu) start_ryu ;;
    web) start_web ;;
    start) start_all ;;
    stop) stop_all ;;
    status) status_all ;;
    mininet) shift || true; run_mininet "${1:-127.0.0.1}" "${2:-6653}" "${3:-4}" "${@:4}" ;;
    logs) show_logs ;;
    rotate-logs) rotate_all_logs ;;
    clean-logs) shift || true; clean_logs "$@" ;;
    clean-pcaps) shift || true; clean_pcaps "$@" ;;
    help|*) usage ;;
  esac
}

main "$@"
