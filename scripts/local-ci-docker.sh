#!/usr/bin/env bash
# =============================================================================
# local-ci-docker.sh — Run local CI inside Docker (GitHub Actions-like Linux).
#
# Usage:
#   ./scripts/local-ci-docker.sh                 # Full local CI in Docker
#   ./scripts/local-ci-docker.sh --fast          # Fast subset in Docker
#   ./scripts/local-ci-docker.sh fmt clippy test # Specific jobs in Docker
#   ./scripts/local-ci-docker.sh --layer core    # Specific layers in Docker
#
# This script is a thin wrapper that runs ./scripts/local-ci.sh in a Linux
# container to better match the GitHub Actions runner environment.
# =============================================================================

set -euo pipefail

# On Windows Git Bash / MSYS, MSYS rewrites POSIX-looking absolute paths
# inside command arguments before exec'ing docker, so `-w /work` becomes
# `-w 'C:/Program Files/Git/work'` and the container fails to start.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Docker Desktop on Windows wants Windows-form host paths in -v binds.
HOST_CARGO_HOME="${HOME}/.cargo"
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        REPO_ROOT="$(cygpath -m "$REPO_ROOT")"
        HOST_CARGO_HOME="$(cygpath -m "$HOME/.cargo")"
        ;;
esac

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker is not installed or not in PATH." >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "Error: docker daemon is not reachable. Start Docker and retry." >&2
    exit 1
fi

# Use an official Rust image so rustup/cargo behavior stays close to CI.
# Extract the pinned channel from rust-toolchain.toml to align host & container toolchains.
PINNED_VERSION="latest"
if [ -f "$REPO_ROOT/rust-toolchain.toml" ]; then
    # Match only `channel = "..."` assignments, not comment lines mentioning "channel".
    extracted_version=$(grep -E '^[[:space:]]*channel[[:space:]]*=' "$REPO_ROOT/rust-toolchain.toml" | head -n1 | sed -E 's/.*=[[:space:]]*["'\'']([^"'\'']+)["'\''].*/\1/' || true)
    if [ -n "$extracted_version" ]; then
        PINNED_VERSION="$extracted_version"
    fi
fi
DOCKER_IMAGE="${LOCAL_CI_DOCKER_IMAGE:-rust:${PINNED_VERSION}}"

# Build inside target/docker-ci so we never execute host/WSL artifacts from target/debug.
# Those binaries may require a newer GLIBC (e.g. 2.38+) than the rust:* image ships.
DOCKER_CARGO_TARGET_DIR="${LOCAL_CI_DOCKER_TARGET_DIR:-target/docker-ci}"
DOCKER_CARGO_TARGET_DIR_CONTAINER="/work/${DOCKER_CARGO_TARGET_DIR}"

echo "Running local CI in Docker image: ${DOCKER_IMAGE}"
echo "Repository: ${REPO_ROOT}"
echo "Cargo target dir (container): ${DOCKER_CARGO_TARGET_DIR_CONTAINER}"
echo ""

# Only request an interactive TTY when one is actually available.
DOCKER_TTY_FLAGS=()
if [[ -t 0 && -t 1 ]]; then
    DOCKER_TTY_FLAGS=(-it)
fi

# Robustly separate options and specific jobs from the arguments.
OPTIONS=()
SPECIFIC_TEST_JOBS=()
SPECIFIC_OTHER_JOBS=()
SPECIFIC_JOBS_SPECIFIED=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            # Run help through one container and exit
            docker run --rm "${DOCKER_TTY_FLAGS[@]}" \
                -e "CARGO_TARGET_DIR=${DOCKER_CARGO_TARGET_DIR_CONTAINER}" \
                -v "${REPO_ROOT}:/work" \
                -v "${REPO_ROOT}/target:/work/target" \
                -w /work \
                "${DOCKER_IMAGE}" \
                bash -c './scripts/local-ci.sh "$@"' _ "$@"
            exit 0
            ;;
        --fast)
            OPTIONS+=("$1")
            shift
            ;;
        --layer)
            OPTIONS+=("$1")
            shift
            if [[ $# -gt 0 ]]; then
                OPTIONS+=("$1")
                shift
            fi
            ;;
        -*)
            OPTIONS+=("$1")
            shift
            ;;
        *)
            SPECIFIC_JOBS_SPECIFIED=true
            if [[ "$1" = "test" || "$1" = "coverage" ]]; then
                SPECIFIC_TEST_JOBS+=("$1")
            else
                SPECIFIC_OTHER_JOBS+=("$1")
            fi
            shift
            ;;
    esac
done

# Determine which jobs to run for each container.
TEST_JOBS=()
OTHER_JOBS=()

if [ "$SPECIFIC_JOBS_SPECIFIED" = true ]; then
    # Only run the specific jobs requested.
    TEST_JOBS=("${SPECIFIC_TEST_JOBS[@]}")
    OTHER_JOBS=("${SPECIFIC_OTHER_JOBS[@]}")
else
    # coverage runs the workspace test suite via cargo llvm-cov test (no separate test job).
    TEST_JOBS=("coverage")
    OTHER_JOBS=("fmt" "clippy" "thumbv7em" "doc" "audit" "deny" "msrv")
fi

OTHER_FAILED=false
if [ ${#OTHER_JOBS[@]} -gt 0 ]; then
    echo "============================================================================="
    echo "Container 1: Running check & lint jobs (${OTHER_JOBS[*]})"
    echo "============================================================================="
    if ! docker run --rm "${DOCKER_TTY_FLAGS[@]}" \
        -e RUST_BACKTRACE=1 \
        -e CARGO_TERM_COLOR=always \
        -e "CARGO_TARGET_DIR=${DOCKER_CARGO_TARGET_DIR_CONTAINER}" \
        -v "${REPO_ROOT}:/work" \
        -v "${HOST_CARGO_HOME}/registry:/usr/local/cargo/registry" \
        -v "${HOST_CARGO_HOME}/git:/usr/local/cargo/git" \
        -v "${REPO_ROOT}/target:/work/target" \
        -w /work \
        "${DOCKER_IMAGE}" \
        bash -c './scripts/local-ci.sh "$@"' _ "${OPTIONS[@]}" "${OTHER_JOBS[@]}"; then
        OTHER_FAILED=true
    fi
    echo ""
fi

TEST_FAILED=false
if [ ${#TEST_JOBS[@]} -gt 0 ]; then
    echo "============================================================================="
    echo "Container 2: Running test jobs (${TEST_JOBS[*]})"
    echo "============================================================================="
    if ! docker run --rm "${DOCKER_TTY_FLAGS[@]}" \
        -e RUST_BACKTRACE=1 \
        -e CARGO_TERM_COLOR=always \
        -e "CARGO_TARGET_DIR=${DOCKER_CARGO_TARGET_DIR_CONTAINER}" \
        -v "${REPO_ROOT}:/work" \
        -v "${HOST_CARGO_HOME}/registry:/usr/local/cargo/registry" \
        -v "${HOST_CARGO_HOME}/git:/usr/local/cargo/git" \
        -v "${REPO_ROOT}/target:/work/target" \
        -w /work \
        "${DOCKER_IMAGE}" \
        bash -c './scripts/local-ci.sh "$@"' _ "${OPTIONS[@]}" "${TEST_JOBS[@]}"; then
        TEST_FAILED=true
    fi
    echo ""
fi

if [ "$OTHER_FAILED" = true ] || [ "$TEST_FAILED" = true ]; then
    echo "Error: One or more local CI containers failed." >&2
    exit 1
fi

echo "All CI containers passed successfully."

