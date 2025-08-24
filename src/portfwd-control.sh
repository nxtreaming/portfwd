#!/bin/sh
#
# portfwd-control.sh - Manages the portfwd daemon
#

# --- Configuration ---
# Path to the portfwd executable (adjust if necessary)
TCPFWD_EXEC="./tcpfwd"
UDPFWD_EXEC="./udpfwd"

# Path to the PID file (must match the -p argument)
PID_FILE="/var/run/portfwd.pid"

# Arguments for the portfwd daemon
# Example: Forward TCP from port 8080 to 127.0.0.1:80
# ARGS="-d -p $PID_FILE 0.0.0.0:8080 127.0.0.1:80"
#
# IMPORTANT: Change this to your desired configuration
ARGS="-d -p $PID_FILE [::]:8080 127.0.0.1:80"

# Choose which forwarder to run: tcpfwd or udpfwd
DAEMON=$TCPFWD_EXEC

# --- Functions ---

check_pid() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if [ -n "$PID" ] && ps -p $PID > /dev/null 2>&1; then
            return 0 # Process is running
        fi
    fi
    return 1 # Process is not running or PID file is missing
}

start() {
    if check_pid; then
        echo "portfwd is already running (PID: $(cat "$PID_FILE"))."
        return 1
    fi

    # Clean up stale PID file if it exists
    if [ -f "$PID_FILE" ]; then
        echo "Removing stale PID file: $PID_FILE"
        rm -f "$PID_FILE"
    fi

    echo "Starting portfwd..."
    $DAEMON $ARGS

    # Wait a moment for the PID file to be created
    sleep 1

    if check_pid; then
        echo "portfwd started successfully (PID: $(cat "$PID_FILE"))."
    else
        echo "Failed to start portfwd."
        return 1
    fi
}

stop() {
    if ! check_pid; then
        echo "portfwd is not running."
        # Clean up stale PID file if it exists
        if [ -f "$PID_FILE" ]; then
            echo "Removing stale PID file: $PID_FILE"
            rm -f "$PID_FILE"
        fi
        return 1
    fi

    PID=$(cat "$PID_FILE")
    echo "Stopping portfwd (PID: $PID)..."
    kill $PID

    # Wait for the process to terminate
    for i in $(seq 1 10); do
        if ! check_pid; then
            echo "portfwd stopped successfully."
            # The daemon should remove its own PID file, but we clean it up just in case
            rm -f "$PID_FILE"
            return 0
        fi
        sleep 1
    done

    echo "portfwd did not stop gracefully. Sending SIGKILL..."
    kill -9 $PID
    rm -f "$PID_FILE"
    echo "portfwd killed."
}

status() {
    if check_pid; then
        echo "portfwd is running (PID: $(cat "$PID_FILE"))."
    else
        echo "portfwd is not running."
    fi
}

# --- Main Logic ---

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac

exit $?
