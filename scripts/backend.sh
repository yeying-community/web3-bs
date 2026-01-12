#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PID_DIR="$ROOT_DIR/.tmp/backend-pids"
LOG_DIR="$ROOT_DIR/.tmp/backend-logs"

mkdir -p "$PID_DIR" "$LOG_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"

pid_file() {
  echo "$PID_DIR/$1.pid"
}

log_file() {
  echo "$LOG_DIR/$1.log"
}

is_running() {
  local name="$1"
  local file
  file="$(pid_file "$name")"
  if [[ ! -f "$file" ]]; then
    return 1
  fi
  local pid
  pid="$(cat "$file" 2>/dev/null || true)"
  if [[ -z "$pid" ]]; then
    return 1
  fi
  if kill -0 "$pid" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

start_service() {
  local name="$1"
  local cmd="$2"
  if is_running "$name"; then
    echo "[$name] already running (pid $(cat "$(pid_file "$name")"))"
    return 0
  fi

  local log
  log="$(log_file "$name")"
  echo "[$name] starting..."
  nohup bash -c "$cmd" >"$log" 2>&1 &
  local pid=$!
  echo "$pid" >"$(pid_file "$name")"

  sleep 0.2
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "[$name] failed to start. Check log: $log"
    rm -f "$(pid_file "$name")"
    return 1
  fi
  echo "[$name] started (pid $pid). Log: $log"
}

stop_service() {
  local name="$1"
  local file
  file="$(pid_file "$name")"

  if ! is_running "$name"; then
    echo "[$name] not running"
    rm -f "$file"
    return 0
  fi

  local pid
  pid="$(cat "$file")"
  echo "[$name] stopping (pid $pid)..."
  kill "$pid" >/dev/null 2>&1 || true

  local tries=0
  while kill -0 "$pid" >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [[ $tries -ge 25 ]]; then
      break
    fi
    sleep 0.2
  done

  if kill -0 "$pid" >/dev/null 2>&1; then
    echo "[$name] forcing stop"
    kill -9 "$pid" >/dev/null 2>&1 || true
  fi

  rm -f "$file"
  echo "[$name] stopped"
}

status_service() {
  local name="$1"
  if is_running "$name"; then
    echo "[$name] running (pid $(cat "$(pid_file "$name")"))"
  else
    echo "[$name] stopped"
  fi
}

require_cmd() {
  local name="$1"
  local bin="$2"
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "[$name] missing dependency: $bin"
    return 1
  fi
  return 0
}

start_node() {
  require_cmd node node || return 1
  start_service node "node \"$ROOT_DIR/examples/backend/node/server.js\""
}

start_go() {
  require_cmd go go || return 1
  start_service go "cd \"$ROOT_DIR/examples/backend/go\" && go run ."
}

start_python() {
  ensure_python_bin || return 1
  start_service python "cd \"$ROOT_DIR/examples/backend/python\" && \"$PYTHON_BIN\" app.py"
}

start_java() {
  require_cmd java java || return 1
  require_cmd java mvn || return 1
  start_service java "cd \"$ROOT_DIR/examples/backend/java\" && mvn -q exec:java -Dexec.mainClass=\"com.yeying.demo.AuthServer\""
}

ensure_python_bin() {
  if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    if command -v python >/dev/null 2>&1; then
      PYTHON_BIN=python
    else
      echo "[python] missing dependency: python3"
      return 1
    fi
  fi
  return 0
}

setup_common() {
  require_cmd setup npm || return 1
  echo "[setup] installing npm dependencies..."
  (cd "$ROOT_DIR" && npm install)
  echo "[setup] building dist..."
  (cd "$ROOT_DIR" && npm run build)
}

setup_go() {
  require_cmd go go || return 1
  echo "[setup] syncing Go modules..."
  (cd "$ROOT_DIR/examples/backend/go" && go mod tidy)
}

setup_python() {
  ensure_python_bin || return 1
  echo "[setup] installing Python dependencies..."
  (cd "$ROOT_DIR/examples/backend/python" && "$PYTHON_BIN" -m pip install -r requirements.txt)
}

setup_java() {
  require_cmd java mvn || return 1
  echo "[setup] building Java project..."
  (cd "$ROOT_DIR/examples/backend/java" && mvn -q -DskipTests package)
}

usage() {
  cat <<USAGE
Usage: ./scripts/backend.sh <start|stop|restart|status> <node|go|python|java|all> [--setup]

Examples:
  ./scripts/backend.sh start node
  ./scripts/backend.sh start node --setup
  ./scripts/backend.sh stop all
  ./scripts/backend.sh restart python
  ./scripts/backend.sh status all

Notes:
  - Logs are under .tmp/backend-logs
  - PIDs are under .tmp/backend-pids
  - Use PORT/JWT_SECRET/ACCESS_TTL_MS/REFRESH_TTL_MS/etc via env vars
  - --setup installs dependencies and builds dist (plus language-specific deps)
USAGE
}

main() {
  if [[ $# -lt 2 ]]; then
    usage
    exit 1
  fi

  local action="$1"
  local target="$2"
  shift 2

  local do_setup=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --setup|--install|--build)
        do_setup=true
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
    shift
  done

  case "$action" in
    start|stop|restart|status) ;;
    *) usage; exit 1 ;;
  esac
  if [[ "$do_setup" == "true" && "$action" != "start" && "$action" != "restart" ]]; then
    echo "--setup is only supported with start/restart"
    exit 1
  fi

  local run_start
  local run_stop
  local run_status
  local run_setup
  local maybe_setup_common
  local setup_common_done=0

  run_start() {
    case "$1" in
      node) start_node ;;
      go) start_go ;;
      python) start_python ;;
      java) start_java ;;
    esac
  }

  run_stop() {
    case "$1" in
      node) stop_service node ;;
      go) stop_service go ;;
      python) stop_service python ;;
      java) stop_service java ;;
    esac
  }

  run_status() {
    case "$1" in
      node) status_service node ;;
      go) status_service go ;;
      python) status_service python ;;
      java) status_service java ;;
    esac
  }

  maybe_setup_common() {
    if [[ "$setup_common_done" -eq 1 ]]; then
      return 0
    fi
    setup_common
    setup_common_done=1
  }

  run_setup() {
    maybe_setup_common
    case "$1" in
      node) ;;
      go) setup_go ;;
      python) setup_python ;;
      java) setup_java ;;
    esac
  }

  local all_targets=(node go python java)
  local targets
  if [[ "$target" == "all" ]]; then
    targets=("${all_targets[@]}")
  else
    targets=("$target")
  fi

  is_target_selected() {
    local needle="$1"
    local t
    for t in "${targets[@]}"; do
      if [[ "$t" == "$needle" ]]; then
        return 0
      fi
    done
    return 1
  }

  stop_other_services() {
    local t
    for t in "${all_targets[@]}"; do
      if ! is_target_selected "$t"; then
        stop_service "$t"
      fi
    done
  }

  case "$action" in
    start)
      stop_other_services
      for t in "${targets[@]}"; do
        if [[ "$do_setup" == "true" ]]; then
          run_setup "$t"
        fi
        run_start "$t"
      done
      ;;
    stop)
      for t in "${targets[@]}"; do
        run_stop "$t"
      done
      ;;
    restart)
      stop_other_services
      for t in "${targets[@]}"; do
        run_stop "$t"
      done
      for t in "${targets[@]}"; do
        if [[ "$do_setup" == "true" ]]; then
          run_setup "$t"
        fi
        run_start "$t"
      done
      ;;
    status)
      for t in "${targets[@]}"; do
        run_status "$t"
      done
      ;;
  esac
}

main "$@"
