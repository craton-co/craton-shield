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
        REPO_ROOT="$(cygpath -w "$REPO_ROOT")"
        HOST_CARGO_HOME="$(cygpath -w "$HOME/.cargo")"
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
DOCKER_IMAGE="${LOCAL_CI_DOCKER_IMAGE:-rust:latest}"

echo "Running local CI in Docker image: ${DOCKER_IMAGE}"
echo "Repository: ${REPO_ROOT}"
echo ""

docker run --rm -it \
    -e RUST_BACKTRACE=1 \
    -e CARGO_TERM_COLOR=always \
    -e CARGO_HOME=/usr/local/cargo \
    -e RUSTUP_HOME=/usr/local/rustup \
    -v "${REPO_ROOT}:/work" \
    -v "${HOST_CARGO_HOME}/registry:/usr/local/cargo/registry" \
    -v "${HOST_CARGO_HOME}/git:/usr/local/cargo/git" \
    -v "${REPO_ROOT}/target:/work/target" \
    -w /work \
    "${DOCKER_IMAGE}" \
    bash -lc 'export PATH=/usr/local/cargo/bin:$PATH; ./scripts/local-ci.sh "$@"' _ "$@"
