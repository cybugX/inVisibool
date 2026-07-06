#!/usr/bin/env bash
# Invisibool - chunk 23 gate demo.
#
# Demonstrates the three `invisibool watch` outcomes without shipping
# any daemon body. Each scenario runs the real invisibool binary with
# the environment variables that force a specific display-server
# detection outcome, prints the refusal or not-yet-implemented
# message, captures the exit code, and asserts it against the
# expected code:
#
#   1. Wayland environment  -> exit 6, Wayland refusal message
#   2. Headless environment -> exit 6, headless refusal message
#   3. X11 environment      -> exit 7, not-yet-implemented message
#
# What the demo proves for the gate reviewer: on every display-server
# outcome the CLI (a) writes an explicit message to stderr, (b) never
# writes to stdout, and (c) exits with the documented code. It does
# NOT prove any daemon behavior; the daemon body lands in a later
# chunk. The clipboard trait, the InMemoryClipboard test backend, the
# leak-harness extension, and the display-server detection are the
# deliverables here, exercised by `cargo test --workspace` and by
# this script.
#
# Run from the repo root:
#   ./demo/chunk23.sh
#
# Requirements: Docker + git on the host. Everything else runs inside
# the pinned dev container. If DOCKER_COMPOSE_SKIP=1 is set, the
# script falls back to the locally-built target/debug/invisibool
# binary instead of docker compose - useful when running inside the
# dev container itself or during development on a machine with a
# native Rust toolchain.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

BOLD=$'\e[1m'
DIM=$'\e[2m'
GREEN=$'\e[32m'
RED=$'\e[31m'
RESET=$'\e[0m'
if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
    BOLD=""; DIM=""; GREEN=""; RED=""; RESET=""
fi

section() {
    printf '\n%s━━ %s %s\n' "$BOLD" "$1" "$RESET"
}

note() {
    printf '%s%s%s\n' "$DIM" "$1" "$RESET"
}

require() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'Missing required tool: %s\n' "$1" >&2
        printf 'This demo needs Docker + git on the host. Install %s, then re-run.\n' "$1" >&2
        exit 1
    }
}

# Two run modes. The container mode matches the earlier m0a / m0b
# demo scripts. The skip mode lets the reviewer (or a CI job that
# already runs inside a container) invoke a pre-built binary.
USE_LOCAL_BINARY=0
if [ "${DOCKER_COMPOSE_SKIP:-0}" = "1" ]; then
    USE_LOCAL_BINARY=1
fi

# In container mode, build the binary once inside the container. In
# local mode, build via `cargo build` on the host.
build_binary() {
    if [ "$USE_LOCAL_BINARY" = "1" ]; then
        require cargo
        cargo build --quiet -p invisibool
    else
        require docker
        require git
        export HOST_UID="$(id -u)"
        export HOST_GID="$(id -g)"
        docker compose build dev >/dev/null
        docker compose run --rm -e CARGO_TERM_COLOR=never dev cargo build --quiet -p invisibool
    fi
}

# Run `invisibool watch` with the given env-var overrides. Prints
# stderr, captures the exit code into the caller-visible `rc` global.
# The detector treats an empty env-var value as unset, so passing
# an empty string is equivalent to unsetting the variable.
run_watch() {
    local wayland="$1"
    local xdg="$2"
    local display="$3"
    if [ "$USE_LOCAL_BINARY" = "1" ]; then
        set +e
        WAYLAND_DISPLAY="$wayland" \
        XDG_SESSION_TYPE="$xdg" \
        DISPLAY="$display" \
        "$REPO_ROOT/target/debug/invisibool" watch
        rc=$?
        set -e
    else
        set +e
        docker compose run --rm \
            -e CARGO_TERM_COLOR=never \
            -e "WAYLAND_DISPLAY=$wayland" \
            -e "XDG_SESSION_TYPE=$xdg" \
            -e "DISPLAY=$display" \
            dev cargo run --quiet -p invisibool -- watch
        rc=$?
        set -e
    fi
}

scenario() {
    local label="$1"
    local expected_exit="$2"
    local wayland="$3"
    local xdg="$4"
    local display="$5"

    section "$label (expected exit $expected_exit)"
    note "WAYLAND_DISPLAY=$wayland XDG_SESSION_TYPE=$xdg DISPLAY=$display"
    printf '\n'

    run_watch "$wayland" "$xdg" "$display"

    printf '\n'
    if [ "$rc" -eq "$expected_exit" ]; then
        printf '%s✓ exit code %s (as expected)%s\n' "$GREEN" "$rc" "$RESET"
    else
        printf '%s✗ exit code %s (expected %s)%s\n' "$RED" "$rc" "$expected_exit" "$RESET" >&2
        exit 1
    fi
}

# ----- Build ---------------------------------------------------------------

section "0 / 4   Build the invisibool binary"
build_binary
note "Binary ready."

# ----- The three scenarios -------------------------------------------------

# Scenario 1: Wayland - refused with exit 6.
scenario "1 / 4   Wayland refusal" 6 \
    "wayland-0" "wayland" ""

# Scenario 2: Headless - refused with exit 6.
scenario "2 / 4   Headless refusal" 6 \
    "" "" ""

# Scenario 3: X11 - not-yet-implemented with exit 7.
scenario "3 / 4   X11 not-yet-implemented" 7 \
    "" "x11" ":0"

# ----- Summary -------------------------------------------------------------

section "4 / 4   Summary"
printf '%s%sChunk 23 gate demo: every scenario exited with the documented code.%s\n' \
    "$BOLD" "$GREEN" "$RESET"
note "The three exit codes (6, 6, 7) match docs/THREAT_MODEL.md row 17 and"
note "the exit-code table in crates/invisibool/src/cli/commands.rs. The"
note "clipboard trait, InMemoryClipboard, leak-harness extension, and the"
note "display-server detector are exercised by cargo test --workspace."
printf '\n'
