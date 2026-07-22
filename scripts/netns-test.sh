#!/usr/bin/env bash
# netns-test.sh — integration test harness for Harper using ip netns + iperf3
#
# Usage:
#   sudo -E ./scripts/netns-test.sh list              # list available tests
#   sudo -E ./scripts/netns-test.sh run <name>         # run one test
#   sudo -E ./scripts/netns-test.sh run all            # run all tests
#   sudo -E ./scripts/netns-test.sh setup_mitm         # bring up MITM topology (interactive)
#   sudo -E ./scripts/netns-test.sh setup_gateway      # bring up Gateway topology (interactive)
#   sudo -E ./scripts/netns-test.sh teardown           # tear down any topology
#
# The -E flag preserves your PATH so nix-shell dependencies (iperf3, jq) are found.
# If you prefer plain `sudo`, set HARPER_BIN to an absolute path first.
#
# Environment:
#   HARPER_BIN   path to harper binary (auto-detected from target/release or target/debug)
#   DEBUG        set to 1 to keep topology up on failure for inspection

set -euo pipefail

if [ -n "${HARPER_BIN:-}" ]; then
    :  # user-specified
elif [ -x ./target/release/harper ]; then
    HARPER_BIN=./target/release/harper
elif [ -x ./target/debug/harper ]; then
    HARPER_BIN=./target/debug/harper
else
    HARPER_BIN=./target/release/harper
fi
DEBUG="${DEBUG:-0}"

BR_LAN="br-harper-lan"
BR_WAN="br-harper-wan"

PREFIX_LAN="192.168.100"
PREFIX_WAN="172.16.0"

TOLERANCE=0.25
TEST_PORT=5201

PIDS=()

cleanup_pids() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    PIDS=()
}

die() { echo "[FAIL] $*" >&2; exit 1; }
info() { echo "[INFO] $*"; }
pass() { echo "[PASS] $*"; }
fail() { echo "[FAIL] $*"; }

check_deps() {
    local missing=0
    for cmd in ip iperf3 jq nft timeout modprobe; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "  missing: $cmd (install via: nix-shell -p $cmd)" >&2
            missing=1
        fi
    done
    if [ ! -x "$HARPER_BIN" ]; then
        echo "  harper binary not found at $HARPER_BIN" >&2
        echo "  build with: cargo build [--release]" >&2
        echo "  or set: HARPER_BIN=/path/to/harper" >&2
        missing=1
    fi
    if [ "$missing" -eq 1 ]; then
        echo "" >&2
        echo "Missing or inaccessible dependencies (see above)." >&2
        echo "When using sudo, pass -E to preserve PATH from nix-shell:" >&2
        echo "  sudo -E ./scripts/netns-test.sh run all" >&2
        echo "Or symlink missing tools into /usr/local/bin." >&2
        exit 1
    fi
}

ns_exists() { ip netns list | grep -qF "$1"; }

wait_for_tc_class() {
    local dev="$1" class="$2" retries="${3:-10}"
    for i in $(seq 1 "$retries"); do
        if tc class show dev "$dev" 2>/dev/null | grep -q "$class"; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

harper_ready() {
    local pid="$1" retries="${2:-15}" has_htb="${3:-1}"
    for i in $(seq 1 "$retries"); do
        if ! kill -0 "$pid" 2>/dev/null; then
            return 1
        fi
        if [ "$has_htb" = "1" ]; then
            if tc qdisc show dev "$BR_LAN" 2>/dev/null | grep -q "htb"; then
                return 0
            fi
        else
            return 0
        fi
        sleep 0.5
    done
    return 1
}

assert_bandwidth() {
    local expected_kbps="$1" json_file="$2" label="${3:-}"
    local tolerance="${4:-$TOLERANCE}"
    local bps
    bps=$(jq -r '.end.sum_received.bits_per_second // .end.sum_sent.bits_per_second // empty' "$json_file" 2>/dev/null)
    if [ -z "$bps" ] || [ "$bps" = "null" ]; then
        fail "$label: no throughput data in iperf3 output"
        return 1
    fi
    local actual_kbps
    actual_kbps=$(awk "BEGIN {printf \"%.0f\", $bps / 1000}")
    local min_kbps
    min_kbps=$(awk "BEGIN {printf \"%.0f\", $expected_kbps * (1 - $tolerance)}")
    local max_kbps
    max_kbps=$(awk "BEGIN {printf \"%.0f\", $expected_kbps * (1 + $tolerance)}")
    if [ "$actual_kbps" -lt "$min_kbps" ] || [ "$actual_kbps" -gt "$max_kbps" ]; then
        fail "$label: expected ~${expected_kbps} Kbps, got ${actual_kbps} Kbps (range ${min_kbps}-${max_kbps})"
        return 1
    fi
    pass "$label: ${actual_kbps} Kbps (expected ~${expected_kbps} Kbps)"
}

assert_near_zero() {
    local json_file="$1" label="${2:-}"
    local bps
    bps=$(jq -r '.end.sum_received.bits_per_second // .end.sum_sent.bits_per_second // 0' "$json_file" 2>/dev/null)
    local kbps
    kbps=$(awk "BEGIN {printf \"%.0f\", $bps / 1000}")
    if [ "$(awk "BEGIN {print ($kbps > 100)}")" = "1" ]; then
        fail "$label: expected near-zero throughput, got ${kbps} Kbps"
        return 1
    fi
    pass "$label: ${kbps} Kbps (blocked)"
}

assert_tc_cleaned() {
    local label="${1:-}"
    if tc qdisc show dev "$BR_LAN" 2>/dev/null | grep -q "htb"; then
        fail "$label: tc qdisc still present on $BR_LAN"
        return 1
    fi
    if ip link show ifb0 2>/dev/null | grep -q "UP"; then
        fail "$label: ifb0 still present"
        return 1
    fi
    pass "$label: tc qdiscs cleaned"
}

# --- Topology: MITM ---

setup_mitm() {
    info "Setting up MITM topology..."

    ip link add name "$BR_LAN" type bridge
    ip link set "$BR_LAN" up
    ip addr add "${PREFIX_LAN}.1/24" dev "$BR_LAN"

    # Victim 1
    ip netns add victim
    ip link add veth.v type veth peer name veth.v-br
    ip link set veth.v netns victim
    ip link set veth.v-br master "$BR_LAN"
    ip link set veth.v-br up
    ip netns exec victim ip link set veth.v up
    ip netns exec victim ip addr add "${PREFIX_LAN}.10/24" dev veth.v
    ip netns exec victim ip link set veth.v addr 02:00:00:00:00:10
    ip netns exec victim ip route add default via "${PREFIX_LAN}.254"

    # Victim 2
    ip netns add victim2
    ip link add veth.v2 type veth peer name veth.v2-br
    ip link set veth.v2 netns victim2
    ip link set veth.v2-br master "$BR_LAN"
    ip link set veth.v2-br up
    ip netns exec victim2 ip link set veth.v2 up
    ip netns exec victim2 ip addr add "${PREFIX_LAN}.11/24" dev veth.v2
    ip netns exec victim2 ip link set veth.v2 addr 02:00:00:00:00:11
    ip netns exec victim2 ip route add default via "${PREFIX_LAN}.254"

    # Gateway
    ip netns add gateway
    ip link add veth.g type veth peer name veth.g-br
    ip link set veth.g netns gateway
    ip link set veth.g-br master "$BR_LAN"
    ip link set veth.g-br up
    ip netns exec gateway ip link set veth.g up
    ip netns exec gateway ip addr add "${PREFIX_LAN}.254/24" dev veth.g
    ip netns exec gateway ip link set veth.g addr 02:00:00:00:00:fe
    ip netns exec gateway sysctl -w net.ipv4.ip_forward=1 >/dev/null

    # Internet (iperf3 server)
    ip netns add internet
    ip link add veth.gw type veth peer name veth.gw-i
    ip link set veth.gw netns gateway
    ip link set veth.gw-i netns internet
    ip netns exec gateway ip link set veth.gw up
    ip netns exec gateway ip addr add "${PREFIX_WAN}.254/24" dev veth.gw
    ip netns exec internet ip link set veth.gw-i up
    ip netns exec internet ip addr add "${PREFIX_WAN}.2/24" dev veth.gw-i
    ip netns exec internet ip route add default via "${PREFIX_WAN}.254"

    # Optional: rp_filter loose on host bridge for MITM forwarding
    sysctl -w net.ipv4.conf."${BR_LAN}".rp_filter=2 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null 2>&1 || true

    info "MITM topology ready: victim(10), victim2(11), gateway(254) <-> internet(2)"
}

# --- Topology: Gateway mode ---

setup_gateway() {
    info "Setting up Gateway topology..."

    ip link add name "$BR_LAN" type bridge
    ip link set "$BR_LAN" up
    ip addr add "${PREFIX_LAN}.1/24" dev "$BR_LAN"

    ip link add name "$BR_WAN" type bridge
    ip link set "$BR_WAN" up
    ip addr add "${PREFIX_WAN}.1/24" dev "$BR_WAN"

    # Client 1
    ip netns add client
    ip link add veth.c1 type veth peer name veth.c1-br
    ip link set veth.c1 netns client
    ip link set veth.c1-br master "$BR_LAN"
    ip link set veth.c1-br up
    ip netns exec client ip link set veth.c1 up
    ip netns exec client ip addr add "${PREFIX_LAN}.10/24" dev veth.c1
    ip netns exec client ip link set veth.c1 addr 02:00:00:00:01:10
    ip netns exec client ip route add default via "${PREFIX_LAN}.1"

    # Client 2
    ip netns add client2
    ip link add veth.c2 type veth peer name veth.c2-br
    ip link set veth.c2 netns client2
    ip link set veth.c2-br master "$BR_LAN"
    ip link set veth.c2-br up
    ip netns exec client2 ip link set veth.c2 up
    ip netns exec client2 ip addr add "${PREFIX_LAN}.11/24" dev veth.c2
    ip netns exec client2 ip link set veth.c2 addr 02:00:00:00:01:11
    ip netns exec client2 ip route add default via "${PREFIX_LAN}.1"

    # Internet (iperf3 server)
    ip netns add internet
    ip link add veth.w type veth peer name veth.w-br
    ip link set veth.w netns internet
    ip link set veth.w-br master "$BR_WAN"
    ip link set veth.w-br up
    ip netns exec internet ip link set veth.w up
    ip netns exec internet ip addr add "${PREFIX_WAN}.2/24" dev veth.w
    ip netns exec internet ip link set veth.w addr 02:00:00:00:02:02
    ip netns exec internet ip route add "${PREFIX_LAN}.0/24" via "${PREFIX_WAN}.1"

    # Enable IP forwarding on host
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sysctl -w net.ipv4.conf."${BR_LAN}".rp_filter=2 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf."${BR_WAN}".rp_filter=2 >/dev/null 2>&1 || true

    info "Gateway topology ready: client(10), client2(11), host is gateway, internet(2)"
}

# --- Teardown ---

teardown() {
    info "Tearing down topology..."

    cleanup_pids
    kill "%iperf3" 2>/dev/null || true

    for ns in victim victim2 client client2 gateway internet; do
        ip netns del "$ns" 2>/dev/null || true
    done
    ip link del "$BR_LAN" 2>/dev/null || true
    ip link del "$BR_WAN" 2>/dev/null || true

    # Clean up any stray veths
    for v in veth.v veth.v-br veth.v2 veth.v2-br veth.g veth.g-br veth.gw veth.gw-i \
             veth.c1 veth.c1-br veth.c2 veth.c2-br veth.w veth.w-br; do
        ip link del "$v" 2>/dev/null || true
    done

    # Clean up harper leftovers (if any)
    tc qdisc del dev "$BR_LAN" root 2>/dev/null || true
    tc qdisc del dev "$BR_LAN" ingress 2>/dev/null || true
    tc qdisc del dev ifb0 root 2>/dev/null || true
    ip link del ifb0 2>/dev/null || true
    nft delete table ip harper 2>/dev/null || true

    info "Teardown complete"
}

# --- iperf3 helpers ---

start_iperf_servers() {
    local ns="${1:-internet}"
    ip netns exec "$ns" iperf3 -s -D -p "$TEST_PORT" 2>/dev/null || true
    sleep 0.5
}

stop_iperf_servers() {
    ip netns exec internet pkill iperf3 2>/dev/null || true
    sleep 0.5
}

run_iperf_client() {
    local ns="$1" server_ip="$2" duration="$3" output_file="$4" label="$5"
    ip netns exec "$ns" \
        timeout "$((duration + 5))" \
        iperf3 -c "$server_ip" -p "$TEST_PORT" -t "$duration" -J \
        > "$output_file" 2>/dev/null || true
}

run_iperf_client_bg() {
    local ns="$1" server_ip="$2" duration="$3" output_file="$4" label="$5"
    ip netns exec "$ns" \
        timeout "$((duration + 5))" \
        iperf3 -c "$server_ip" -p "$TEST_PORT" -t "$duration" -J \
        > "$output_file" 2>/dev/null || true &
    PIDS+=($!)
}

# --- Harper helpers ---

start_harper() {
    local args="$*"
    local has_htb=1
    if ! echo "$args" | grep -Eq -- '(-b|--pool)'; then
        has_htb=0
    fi
    if [ -n "$args" ]; then
        "$HARPER_BIN" $args &
    else
        "$HARPER_BIN" &
    fi
    local pid=$!
    if ! harper_ready "$pid" 20 "$has_htb"; then
        kill "$pid" 2>/dev/null || true
        die "harper failed to start (PID $pid)"
    fi
    echo "$pid"
}

start_harper_bg() {
    local args="$*"
    if [ -n "$args" ]; then
        "$HARPER_BIN" $args &
    else
        "$HARPER_BIN" &
    fi
    local pid=$!
    PIDS+=($pid)
    echo "$pid"
}

stop_harper() {
    local pid="$1"
    kill "$pid" 2>/dev/null || true
    sleep 2
    if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
}

# ====================================================================
# Test functions
# ====================================================================

test_mitm_single_shape() {
    info "=== MITM: single victim, bandwidth cap ==="
    teardown
    setup_mitm
    start_iperf_servers

    local pid
    pid=$(start_harper "-i $BR_LAN -t ${PREFIX_LAN}.10 -g ${PREFIX_LAN}.254 -b 1024 --userland")

    run_iperf_client victim "${PREFIX_WAN}.2" 10 "/tmp/harper_test_mitm_single.json"
    assert_bandwidth 1024 "/tmp/harper_test_mitm_single.json" "mitm_single_shape"

    stop_harper "$pid"
    assert_tc_cleaned "mitm_single_shape"
    stop_iperf_servers
    teardown
}

test_mitm_multi_shape() {
    info "=== MITM: two victims, independent caps ==="
    teardown
    setup_mitm
    start_iperf_servers

    local pid
    pid=$(start_harper "-i $BR_LAN -t ${PREFIX_LAN}.10 -t ${PREFIX_LAN}.11 -g ${PREFIX_LAN}.254 -b 512 --userland")

    run_iperf_client victim "${PREFIX_WAN}.2" 10 "/tmp/harper_test_mitm_multi_v1.json"
    assert_bandwidth 512 "/tmp/harper_test_mitm_multi_v1.json" "mitm_multi_shape (victim1)"

    run_iperf_client victim2 "${PREFIX_WAN}.2" 10 "/tmp/harper_test_mitm_multi_v2.json"
    assert_bandwidth 512 "/tmp/harper_test_mitm_multi_v2.json" "mitm_multi_shape (victim2)"

    stop_harper "$pid"
    assert_tc_cleaned "mitm_multi_shape"
    stop_iperf_servers
    teardown
}

test_mitm_block() {
    info "=== MITM: block victim (0 kbps) ==="
    teardown
    setup_mitm
    start_iperf_servers

    local pid
    pid=$(start_harper "-i $BR_LAN -t ${PREFIX_LAN}.10 -g ${PREFIX_LAN}.254 -b 0 --userland")

    run_iperf_client victim "${PREFIX_WAN}.2" 10 "/tmp/harper_test_mitm_block.json" || true
    assert_near_zero "/tmp/harper_test_mitm_block.json" "mitm_block"

    stop_harper "$pid"
    assert_tc_cleaned "mitm_block"
    stop_iperf_servers
    teardown
}

test_mitm_passthrough() {
    info "=== MITM: passthrough (no bandwidth cap, verify connectivity) ==="
    teardown
    setup_mitm
    start_iperf_servers

    local pid
    pid=$(start_harper "-i $BR_LAN -t ${PREFIX_LAN}.10 -g ${PREFIX_LAN}.254 --userland")

    run_iperf_client victim "${PREFIX_WAN}.2" 10 "/tmp/harper_test_mitm_pass.json"
    local bps
    bps=$(jq -r '.end.sum_received.bits_per_second // 0' /tmp/harper_test_mitm_pass.json)
    local kbps
    kbps=$(awk "BEGIN {printf \"%.0f\", $bps / 1000}")
    if [ "$(awk "BEGIN {print ($kbps > 10000 ? 1 : 0)}")" = "1" ]; then
        pass "mitm_passthrough: ${kbps} Kbps (uncapped)"
    else
        fail "mitm_passthrough: only ${kbps} Kbps (expected > 10000)"
    fi

    stop_harper "$pid"
    assert_tc_cleaned "mitm_passthrough"
    stop_iperf_servers
    teardown
}

test_gateway_single() {
    info "=== Gateway: single client, bandwidth cap ==="
    teardown
    setup_gateway
    start_iperf_servers

    local pid
    pid=$(start_harper "--gateway-mode -i $BR_LAN -t ${PREFIX_LAN}.10 -b 1024")

    run_iperf_client client "${PREFIX_WAN}.2" 10 "/tmp/harper_test_gw_single.json"
    assert_bandwidth 1024 "/tmp/harper_test_gw_single.json" "gateway_single"

    stop_harper "$pid"
    assert_tc_cleaned "gateway_single"
    stop_iperf_servers
    teardown
}

test_gateway_multi() {
    info "=== Gateway: two clients, independent caps ==="
    teardown
    setup_gateway
    start_iperf_servers

    local pid
    pid=$(start_harper "--gateway-mode -i $BR_LAN -t ${PREFIX_LAN}.10 -t ${PREFIX_LAN}.11 -b 512")

    run_iperf_client client "${PREFIX_WAN}.2" 10 "/tmp/harper_test_gw_multi_c1.json"
    assert_bandwidth 512 "/tmp/harper_test_gw_multi_c1.json" "gateway_multi (client1)"

    run_iperf_client client2 "${PREFIX_WAN}.2" 10 "/tmp/harper_test_gw_multi_c2.json"
    assert_bandwidth 512 "/tmp/harper_test_gw_multi_c2.json" "gateway_multi (client2)"

    stop_harper "$pid"
    assert_tc_cleaned "gateway_multi"
    stop_iperf_servers
    teardown
}

test_gateway_pool() {
    info "=== Gateway: shared pool mode ==="
    teardown
    setup_gateway
    start_iperf_servers

    local pool_kbps=2048
    local pid
    pid=$(start_harper "--gateway-mode -i $BR_LAN -t ${PREFIX_LAN}.10 -t ${PREFIX_LAN}.11 --pool $pool_kbps")

    cleanup_pids
    run_iperf_client_bg client "${PREFIX_WAN}.2" 12 "/tmp/harper_test_gw_pool_c1.json"
    run_iperf_client_bg client2 "${PREFIX_WAN}.2" 12 "/tmp/harper_test_gw_pool_c2.json"
    for p in "${PIDS[@]:-}"; do wait "$p" 2>/dev/null || true; done
    PIDS=()

    local bps1 bps2
    bps1=$(jq -r '.end.sum_received.bits_per_second // 0' /tmp/harper_test_gw_pool_c1.json)
    bps2=$(jq -r '.end.sum_received.bits_per_second // 0' /tmp/harper_test_gw_pool_c2.json)
    local total_kbps
    total_kbps=$(awk "BEGIN {printf \"%.0f\", ($bps1 + $bps2) / 1000}")
    local max_kbps
    max_kbps=$(awk "BEGIN {printf \"%.0f\", $pool_kbps * (1 + $TOLERANCE)}")

    if [ "$total_kbps" -le "$max_kbps" ]; then
        pass "gateway_pool: combined ${total_kbps} Kbps ≤ ${max_kbps} Kbps (pool=${pool_kbps} Kbps)"
    else
        fail "gateway_pool: combined ${total_kbps} Kbps exceeds ${max_kbps} Kbps"
    fi

    stop_harper "$pid"
    assert_tc_cleaned "gateway_pool"
    stop_iperf_servers
    teardown
}

test_gateway_uplink_exclude() {
    info "=== Gateway: uplink exclusion (exclude host from victim pool) ==="
    teardown
    setup_gateway
    start_iperf_servers

    local pool_kbps=2048
    local pid
    pid=$(start_harper "--gateway-mode -i $BR_LAN -t ${PREFIX_LAN}.10 -t ${PREFIX_LAN}.11 --pool $pool_kbps --uplink ${PREFIX_LAN}.1")

    run_iperf_client client "${PREFIX_WAN}.2" 10 "/tmp/harper_test_gw_uplink.json"
    assert_bandwidth "$pool_kbps" "/tmp/harper_test_gw_uplink.json" "gateway_uplink_exclude (single client)"

    stop_harper "$pid"
    assert_tc_cleaned "gateway_uplink_exclude"
    stop_iperf_servers
    teardown
}

test_gateway_block() {
    info "=== Gateway: block client (0 kbps) ==="
    teardown
    setup_gateway
    start_iperf_servers

    local pid
    pid=$(start_harper "--gateway-mode -i $BR_LAN -t ${PREFIX_LAN}.10 -b 0")

    run_iperf_client client "${PREFIX_WAN}.2" 10 "/tmp/harper_test_gw_block.json" || true
    assert_near_zero "/tmp/harper_test_gw_block.json" "gateway_block"

    stop_harper "$pid"
    assert_tc_cleaned "gateway_block"
    stop_iperf_servers
    teardown
}

# ====================================================================
# Main
# ====================================================================

AVAILABLE_TESTS=(
    mitm_single_shape
    mitm_multi_shape
    mitm_block
    mitm_passthrough
    gateway_single
    gateway_multi
    gateway_pool
    gateway_uplink_exclude
    gateway_block
)

list_tests() {
    echo "Available tests:"
    for t in "${AVAILABLE_TESTS[@]}"; do
        echo "  $t"
    done
}

run_test() {
    local name="$1"
    case "$name" in
        mitm_single_shape)      test_mitm_single_shape ;;
        mitm_multi_shape)       test_mitm_multi_shape ;;
        mitm_block)             test_mitm_block ;;
        mitm_passthrough)       test_mitm_passthrough ;;
        gateway_single)         test_gateway_single ;;
        gateway_multi)          test_gateway_multi ;;
        gateway_pool)           test_gateway_pool ;;
        gateway_uplink_exclude) test_gateway_uplink_exclude ;;
        gateway_block)          test_gateway_block ;;
        *) die "unknown test: $name (use: list)" ;;
    esac
}

run_all() {
    local passed=0 failed=0
    for t in "${AVAILABLE_TESTS[@]}"; do
        info "========================================"
        info "Running: $t"
        info "========================================"
        if run_test "$t"; then
            ((passed++))
        else
            ((failed++))
            if [ "$DEBUG" -eq 0 ]; then
                teardown
            else
                info "DEBUG=1, keeping topology up for $t"
            fi
        fi
    done
    info "========================================"
    info "Results: $passed passed, $failed failed"
    info "========================================"
    return "$failed"
}

main() {
    case "${1:-help}" in
        list)
            list_tests
            ;;
        help|--help)
            echo "Usage:"
            echo "  $0 list"
            echo "  $0 run <name|all>"
            echo "  $0 setup_mitm"
            echo "  $0 setup_gateway"
            echo "  $0 teardown"
            echo ""
            list_tests
            ;;
        *)
            if [ "$EUID" -ne 0 ]; then
                die "$0 $1 requires root (try: sudo $0 $*)"
            fi
            check_deps

            case "${1:-help}" in
                run)
                    if [ "${2:-}" = "all" ]; then
                        run_all; local rc=$?
                        [ "$rc" -gt 0 ] && exit "$rc" || :
                    elif [ -n "${2:-}" ]; then
                        run_test "$2"
                    else
                        die "usage: $0 run <name|all>"
                    fi
                    ;;
                setup_mitm)
                    teardown
                    setup_mitm
                    echo "Topology is up. Press Ctrl-C to teardown."
                    trap teardown EXIT
                    sleep infinity
                    ;;
                setup_gateway)
                    teardown
                    setup_gateway
                    echo "Topology is up. Press Ctrl-C to teardown."
                    trap teardown EXIT
                    sleep infinity
                    ;;
                teardown)
                    teardown
                    ;;
                *)
                    echo "Usage:"
                    echo "  $0 list"
                    echo "  $0 run <name|all>"
                    echo "  $0 setup_mitm"
                    echo "  $0 setup_gateway"
                    echo "  $0 teardown"
                    echo ""
                    list_tests
                    ;;
            esac
            ;;
    esac
}

main "$@"
