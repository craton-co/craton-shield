#!/usr/bin/env bash
# =============================================================================
# local-ci.sh — Run all GitHub Actions CI checks locally before pushing.
#
# Usage:
#   ./scripts/local-ci.sh                    # Run all jobs for all layers
#   ./scripts/local-ci.sh fmt test           # Run specific jobs only
#   ./scripts/local-ci.sh --fast             # Skip slow jobs (coverage, audit, msrv)
#   ./scripts/local-ci.sh coverage           # Tests + lcov in one pass (no separate test job)
#   ./scripts/local-ci.sh --layer core coverage
#   ./scripts/local-ci.sh --coverage-lib-only coverage  # Faster, lib tests only
#   ./scripts/local-ci.sh --layer core       # Run only core layer
#   ./scripts/local-ci.sh --layer auto,emb   # Run only auto + embedded layers
#
# Replicates every job from .github/workflows/ci.yml:
#   fmt, clippy, test, thumbv7em, doc, audit, deny, msrv, coverage
#
# Layers: core, auto, emb (embedded), ind (industrial), all (default)
#
# Skips (requires Linux / GitHub-only):
#   - aarch64 cross-compilation (needs QEMU + cross-compiler)
#   - test-hal-linux (needs Linux vcan0 kernel module)
#   - Codecov upload (needs token)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TOTAL_TIME=0
RESULTS=()

JOBS_TO_RUN=()
FAST_MODE=false
COVERAGE_LIB_ONLY=false
LAYERS=()
VALID_JOBS=(fmt clippy test thumbv7em doc audit deny msrv coverage)
VALID_LAYERS=(core auto emb ind all)

# no_std crate lists per layer (must match .github/workflows/ci.yml)
NOSTD_CORE=(vs-types vs-crypto vs-can-monitor vs-eth-monitor vs-netfw vs-policy-engine vs-event-logger vs-runtime)
NOSTD_AUTO=(vs-types-auto vs-signal-ids)
NOSTD_EMB=(vs-types-embedded vs-mqtt-monitor vs-coap-monitor vs-runtime-embedded)
NOSTD_IND=(vs-types-ind vs-modbus-monitor-ind vs-runtime-ind)

# Workspace packages per layer for scoped coverage (cargo llvm-cov -p …).
COV_CORE=(vs-types vs-health vs-crypto vs-key-manager vs-secure-boot vs-can-monitor vs-eth-monitor
    vs-ids-engine vs-anomaly vs-integrity vs-netfw vs-ota-validator vs-event-logger vs-policy-engine
    vs-runtime vs-ffi vs-storage vs-hal vs-hal-linux vs-evidence-envelope vs-report-iec62443
    vs-report-iso21434 vs-report-iec62304)
COV_AUTO=(vs-types-auto vs-autosar vs-v2x vs-signal-ids vs-diag-gateway vs-runtime-auto vs-ffi-auto)
COV_EMB=(vs-types-embedded vs-mqtt-monitor vs-coap-monitor vs-ble-monitor vs-zigbee-monitor
    vs-lora-monitor vs-modbus-monitor-emb vs-runtime-embedded)
COV_IND=(vs-types-ind vs-modbus-monitor-ind vs-opcua-monitor vs-profinet-monitor vs-ethernetip-monitor
    vs-dnp3-monitor vs-bacnet-monitor vs-runtime-ind vs-s7comm-monitor vs-iec60870-monitor
    vs-iec61850-monitor)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

is_valid_job() {
    local job="$1"
    for v in "${VALID_JOBS[@]}"; do
        [[ "$v" = "$job" ]] && return 0
    done
    return 1
}

is_valid_layer() {
    local layer="$1"
    for v in "${VALID_LAYERS[@]}"; do
        [[ "$v" = "$layer" ]] && return 0
    done
    return 1
}

layer_enabled() {
    local layer="$1"
    [[ ${#LAYERS[@]} -eq 0 ]] && return 0          # no filter = all
    for l in "${LAYERS[@]}"; do
        [[ "$l" = "all" || "$l" = "$layer" ]] && return 0
    done
    return 1
}

# Append -p flags for enabled layers into COVERAGE_PACKAGE_ARGS.
# When no --layer filter is set, leaves COVERAGE_PACKAGE_ARGS empty (= use --workspace).
coverage_collect_package_args() {
    COVERAGE_PACKAGE_ARGS=()
    [[ ${#LAYERS[@]} -eq 0 ]] && return 0

    if layer_enabled core; then
        for pkg in "${COV_CORE[@]}"; do
            COVERAGE_PACKAGE_ARGS+=(-p "$pkg")
        done
    fi
    if layer_enabled auto; then
        for pkg in "${COV_AUTO[@]}"; do
            COVERAGE_PACKAGE_ARGS+=(-p "$pkg")
        done
    fi
    if layer_enabled emb; then
        for pkg in "${COV_EMB[@]}"; do
            COVERAGE_PACKAGE_ARGS+=(-p "$pkg")
        done
    fi
    if layer_enabled ind; then
        for pkg in "${COV_IND[@]}"; do
            COVERAGE_PACKAGE_ARGS+=(-p "$pkg")
        done
    fi
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fast) FAST_MODE=true; shift ;;
        --coverage-lib-only) COVERAGE_LIB_ONLY=true; shift ;;
        --layer)
            shift
            IFS=',' read -ra _layers <<< "${1:?--layer requires a value}"
            for _l in "${_layers[@]}"; do
                if is_valid_layer "$_l"; then
                    LAYERS+=("$_l")
                else
                    printf "${RED}Error: unknown layer '%s'${RESET}\n" "$_l" >&2
                    printf "Valid layers: %s\n" "${VALID_LAYERS[*]}" >&2
                    exit 1
                fi
            done
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--fast] [--layer LAYERS] [job1 job2 ...]"
            echo ""
            echo "Jobs:   ${VALID_JOBS[*]}"
            echo "Layers: ${VALID_LAYERS[*]}  (comma-separated, default: all)"
            echo ""
            echo "  --fast                 Skip slow jobs (coverage, audit, msrv)"
            echo "  --layer core,auto      Run only specific layers (tests + coverage)"
            echo "  --coverage-lib-only    Coverage: unit tests in lib/ only (faster, less complete)"
            echo ""
            echo "  coverage runs the test suite via cargo llvm-cov test; if both test and"
            echo "  coverage are requested, the standalone test job is skipped."
            exit 0
            ;;
        *)
            if is_valid_job "$1"; then
                JOBS_TO_RUN+=("$1")
            else
                printf "${RED}Error: unknown job '%s'${RESET}\n" "$1" >&2
                printf "Valid jobs: %s\n" "${VALID_JOBS[*]}" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

# Default job set
if [[ ${#JOBS_TO_RUN[@]} -eq 0 ]]; then
    if [[ "$FAST_MODE" = true ]]; then
        JOBS_TO_RUN=(fmt clippy test thumbv7em doc)
    else
        JOBS_TO_RUN=(fmt clippy test thumbv7em doc audit deny msrv coverage)
    fi
fi

should_run() {
    local job="$1"
    for j in "${JOBS_TO_RUN[@]}"; do
        [[ "$j" = "$job" ]] && return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# Job runner
# ---------------------------------------------------------------------------

run_job() {
    local name="$1"; shift
    local description="$1"; shift

    printf "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
    printf "${BOLD}▶ [%s] %s${RESET}\n" "$name" "$description"
    printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"

    local start_time end_time elapsed
    start_time=$(date +%s)

    if "$@"; then
        end_time=$(date +%s)
        elapsed=$((end_time - start_time))
        TOTAL_TIME=$((TOTAL_TIME + elapsed))
        PASS_COUNT=$((PASS_COUNT + 1))
        RESULTS+=("${GREEN}✓${RESET} ${name} (${elapsed}s)")
        printf "\n${GREEN}✓ [%s] PASSED${RESET} (%ds)\n" "$name" "$elapsed"
    else
        end_time=$(date +%s)
        elapsed=$((end_time - start_time))
        TOTAL_TIME=$((TOTAL_TIME + elapsed))
        FAIL_COUNT=$((FAIL_COUNT + 1))
        RESULTS+=("${RED}✗${RESET} ${name} (${elapsed}s)")
        printf "\n${RED}✗ [%s] FAILED${RESET} (%ds)\n" "$name" "$elapsed"
    fi
}

skip_job() {
    local name="$1"
    local reason="$2"
    SKIP_COUNT=$((SKIP_COUNT + 1))
    RESULTS+=("${YELLOW}⊘${RESET} ${name} (skipped: ${reason})")
    printf "\n${YELLOW}⊘ [%s] SKIPPED${RESET} — %s\n" "$name" "$reason"
}

# ---------------------------------------------------------------------------
# Job definitions
# ---------------------------------------------------------------------------

job_fmt() {
    cargo fmt --all -- --check
}

job_clippy() {
    cargo clippy --workspace --all-targets -- -D warnings
}

job_test() {
    cargo test --workspace
}

job_thumbv7em() {
    if ! rustup target list --installed | grep -q thumbv7em-none-eabihf; then
        echo "Installing thumbv7em-none-eabihf target..."
        rustup target add thumbv7em-none-eabihf
    fi

    local failed=false

    if layer_enabled core; then
        echo "  Checking core crates..."
        for crate in "${NOSTD_CORE[@]}"; do
            cargo check --target thumbv7em-none-eabihf -p "$crate" || failed=true
        done
    fi

    if layer_enabled auto; then
        echo "  Checking auto crates..."
        for crate in "${NOSTD_AUTO[@]}"; do
            cargo check --target thumbv7em-none-eabihf -p "$crate" || failed=true
        done
    fi

    if layer_enabled emb; then
        echo "  Checking embedded crates..."
        for crate in "${NOSTD_EMB[@]}"; do
            cargo check --target thumbv7em-none-eabihf -p "$crate" || failed=true
        done
    fi

    if layer_enabled ind; then
        echo "  Checking industrial crates..."
        for crate in "${NOSTD_IND[@]}"; do
            cargo check --target thumbv7em-none-eabihf -p "$crate" || failed=true
        done
    fi

    [[ "$failed" = false ]]
}

job_doc() {
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
}

job_audit() {
    if ! rustup toolchain list | grep -q "^stable"; then
        echo "Installing stable toolchain for cargo-audit..."
        rustup toolchain install stable --profile minimal
    fi

    if ! cargo +stable audit --version &>/dev/null; then
        echo "Installing cargo-audit..."
        cargo +stable install cargo-audit --locked
    fi
    # Use a separate DB path to avoid conflicts with cargo-deny's advisory DB cache
    cargo +stable audit --db "${CARGO_HOME:-$HOME/.cargo}/advisory-db-audit"
}

job_deny() {
    if ! rustup toolchain list | grep -q "^stable"; then
        echo "Installing stable toolchain for cargo-deny..."
        rustup toolchain install stable --profile minimal
    fi

    if ! cargo +stable deny --version &>/dev/null; then
        echo "Installing cargo-deny..."
        cargo +stable install cargo-deny --locked
    fi

    # Workaround: cargo-deny's advisory DB parser fails on CRLF line endings.
    # On Windows with core.autocrlf=true, the cloned DB gets CRLF — fix it.
    local db_dir
    db_dir=$(find "${CARGO_HOME:-$HOME/.cargo}/advisory-db" -maxdepth 1 -name "advisory-db-*" -type d 2>/dev/null | head -1)
    if [[ -n "$db_dir" && -d "$db_dir/.git" ]]; then
        local current_autocrlf
        current_autocrlf=$(git -C "$db_dir" config --get core.autocrlf 2>/dev/null || echo "")
        if [[ "$current_autocrlf" != "false" ]]; then
            echo "Fixing CRLF in advisory DB cache..."
            git -C "$db_dir" config core.autocrlf false
            git -C "$db_dir" rm --cached -r . > /dev/null 2>&1 || true
            git -C "$db_dir" reset --hard HEAD > /dev/null 2>&1 || true
        fi
    fi

    cargo +stable deny check
}

job_msrv() {
    local msrv="1.82.0"

    if ! rustup toolchain list | grep -q "$msrv"; then
        echo "Installing Rust $msrv toolchain..."
        rustup toolchain install "$msrv" --profile minimal
    fi

    cargo +"$msrv" check --workspace
}

job_coverage() {
    if ! command -v cargo-llvm-cov &>/dev/null; then
        echo "Installing cargo-llvm-cov..."
        cargo install cargo-llvm-cov --version 0.6.16 --locked
    fi

    if ! rustup component add llvm-tools-preview; then
        echo "Warning: failed to add llvm-tools-preview component" >&2
    fi

    coverage_collect_package_args

    local -a llvm_args=(test)
    if [[ ${#COVERAGE_PACKAGE_ARGS[@]} -gt 0 ]]; then
        llvm_args+=("${COVERAGE_PACKAGE_ARGS[@]}")
        echo "Coverage scope: ${#COVERAGE_PACKAGE_ARGS[@]} package(s) (layer filter)"
    else
        llvm_args+=(--workspace)
        echo "Coverage scope: full workspace"
    fi
    if [[ "$COVERAGE_LIB_ONLY" = true ]]; then
        llvm_args+=(--lib)
        echo "Coverage mode: lib unit tests only (--coverage-lib-only)"
    else
        echo "Coverage mode: all tests (unit + integration)"
    fi

    local cov_output="target/lcov.info"
    llvm_args+=(--lcov --output-path "$cov_output")

    echo "Running tests once under LLVM instrumentation (cargo llvm-cov test)..."
    cargo llvm-cov "${llvm_args[@]}"
    echo ""
    echo "Coverage report written to $cov_output"

    if [ -f "$cov_output" ]; then
        local lines hit
        lines=$(grep -c "^DA:" "$cov_output" 2>/dev/null || echo 0)
        hit=$(grep "^DA:" "$cov_output" 2>/dev/null | grep -cv ",0$" || echo 0)
        if [ "$lines" -gt 0 ]; then
            local pct=$((hit * 100 / lines))
            echo "Line coverage: $hit / $lines ($pct%)"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Trap for clean interruption
# ---------------------------------------------------------------------------

print_partial_results() {
    printf "\n\n${YELLOW}${BOLD}Interrupted!${RESET} Partial results:\n"
    for result in "${RESULTS[@]}"; do
        printf "  %b\n" "$result"
    done
    printf "\n"
    exit 130
}

trap print_partial_results INT TERM

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

LAYER_DISPLAY="all"
if [[ ${#LAYERS[@]} -gt 0 ]]; then
    LAYER_DISPLAY=$(IFS=,; echo "${LAYERS[*]}")
fi

printf "${BOLD}${CYAN}"
printf "╔══════════════════════════════════════════════════════════╗\n"
printf "║        Craton Shield Local CI Runner                    ║\n"
printf "║        Replicates .github/workflows/ci.yml              ║\n"
printf "╚══════════════════════════════════════════════════════════╝\n"
printf "${RESET}"
printf "Platform: %s %s\n" "$(uname -s)" "$(uname -m)"
printf "Rust:     %s\n" "$(rustc --version)"
printf "Jobs:     %s\n" "${JOBS_TO_RUN[*]}"
printf "Layers:   %s\n" "$LAYER_DISPLAY"

# Run each job
if should_run fmt; then
    run_job "fmt" "Check formatting (cargo fmt)" job_fmt
fi
if should_run clippy; then
    run_job "clippy" "Lint (clippy, deny warnings)" job_clippy
fi
if should_run test; then
    if should_run coverage; then
        skip_job "test" "tests run inside coverage (cargo llvm-cov test)"
    else
        run_job "test" "Run all tests" job_test
    fi
fi
if should_run thumbv7em; then
    run_job "thumbv7em" "Check no_std (Cortex-M target)" job_thumbv7em
fi
if should_run doc; then
    run_job "doc" "Build docs (warnings = errors)" job_doc
fi
if should_run audit; then
    run_job "audit" "Security audit (cargo audit)" job_audit
fi
if should_run deny; then
    run_job "deny" "Dependency policy (cargo deny)" job_deny
fi
if should_run msrv; then
    run_job "msrv" "Check MSRV (Rust 1.82.0)" job_msrv
fi
if should_run coverage; then
    run_job "coverage" "Code coverage (cargo-llvm-cov)" job_coverage
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

printf "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
printf "${BOLD}Summary${RESET}\n"
printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n\n"

for result in "${RESULTS[@]}"; do
    printf "  %b\n" "$result"
done

printf "\n"
printf "  Passed:  ${GREEN}%d${RESET}\n" "$PASS_COUNT"
printf "  Failed:  ${RED}%d${RESET}\n" "$FAIL_COUNT"
printf "  Skipped: ${YELLOW}%d${RESET}\n" "$SKIP_COUNT"
printf "  Total time: %ds\n\n" "$TOTAL_TIME"

if [ "$FAIL_COUNT" -gt 0 ]; then
    printf "${RED}${BOLD}CI FAILED${RESET} — fix the errors above before pushing.\n\n"
    exit 1
else
    printf "${GREEN}${BOLD}CI PASSED${RESET} — safe to push.\n\n"
    exit 0
fi
