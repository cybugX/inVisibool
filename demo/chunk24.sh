#!/usr/bin/env bash
# Invisibool - chunk 24 gate demo (X11 clipboard backend).
#
# Exercises the X11 backend end-to-end under Xvfb. Each scenario runs
# a small cross-check between our backend and xclip (the reference
# X11 clipboard tool):
#
#   1. Our backend writes text; xclip reads it back byte-exact.
#   2. xclip owns 1 MiB via INCR; our backend reads it back
#      byte-exact via the INCR reader path (the failure the design
#      review's INCR probe exposed - now closed).
#   3. xclip owns 10 MiB (over cap); our backend refuses with a
#      typed error in plain language rather than silently truncating.
#   4. Our clear() disowns the selection; xclip -o returns nothing.
#   5. A subscribe callback that itself calls read_text completes
#      (the dispatcher-vs-event-thread deadlock regression from the
#      round-2 review is closed).
#
# Run from the repo root:
#   ./demo/chunk24.sh
#
# Requirements: Docker + git on the host. Everything else runs inside
# the pinned dev container (which now includes Xvfb + xclip). If
# DOCKER_COMPOSE_SKIP=1 is set, the script falls back to the locally-
# built cargo test invocation, requires Xvfb + xclip on the host.

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
        exit 1
    }
}

USE_LOCAL=0
if [ "${DOCKER_COMPOSE_SKIP:-0}" = "1" ]; then
    USE_LOCAL=1
fi

run_tests_in_env() {
    if [ "$USE_LOCAL" = "1" ]; then
        require cargo
        require Xvfb
        require xclip
        # Strict: the tools ARE available, so silent-skip must not fire.
        INVISIBOOL_REQUIRE_X_TOOLS=1 cargo test -p invisibool-clipboard --test x11_integration --quiet 2>&1
    else
        require docker
        require git
        export HOST_UID="$(id -u)"
        export HOST_GID="$(id -g)"
        docker compose build dev >/dev/null
        # Strict: the container was built with xvfb + xclip. If a
        # future image loses them, this makes the tests panic loudly
        # rather than pass 11 skips.
        docker compose run --rm \
            -e CARGO_TERM_COLOR=never \
            -e INVISIBOOL_REQUIRE_X_TOOLS=1 \
            dev cargo test -p invisibool-clipboard --test x11_integration --quiet 2>&1
    fi
}

# ----- Preflight ---------------------------------------------------------

section "0 / 2   Environment"
if [ "$USE_LOCAL" = "1" ]; then
    note "Running against the locally-built binary (DOCKER_COMPOSE_SKIP=1)."
else
    note "Running inside the pinned dev container."
fi

# ----- Test suite --------------------------------------------------------

section "1 / 2   X11 integration suite (Xvfb + xclip)"
note "The suite covers: plain writes and reads, 1 MiB INCR round-trip,"
note "10 MiB over-cap refusal (typed error, plain language, never truncated),"
note "clear disowns, subscribe fires on external + our own writes,"
note "callback-calls-read_text without deadlock, TIMESTAMP and TARGETS interop."
echo
if run_tests_in_env; then
    printf '\n%s%s✓ Every X11 backend behavior verified via xclip cross-check.%s\n' \
        "$BOLD" "$GREEN" "$RESET"
else
    printf '\n%s%s✗ At least one X11 backend check failed.%s\n' \
        "$BOLD" "$RED" "$RESET" >&2
    exit 1
fi

# ----- Summary -----------------------------------------------------------

section "2 / 2   Summary"
note "Chunk 24's backend passes every behavioral claim under Xvfb. The daemon"
note "body lands with a later chunk; watch on this platform still exits 7 (not"
note "yet implemented) because there is no daemon to run. What this chunk"
note "delivers is the trait implementation and the INCR-safe read/write path."
printf '\n'
