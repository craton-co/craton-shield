#!/usr/bin/env bash
# =============================================================================
# local-ci.sh — Run all GitHub Actions CI checks locally before pushing.
#
# Usage:
#   ./scripts/local-ci.sh          # Run all jobs
#   ./scripts/local-ci.sh fmt test # Run specific jobs only
#   ./scripts/local-ci.sh --fast   # Skip slow jobs (coverage, audit, msrv)
#
# Replicates every job from .github/workflows/ci.yml:
#   fmt, clippy, test, check-thumbv7em, doc, security-audit, deny, msrv, coverage
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

# Default: run all jobs
JOBS_TO_RUN=()
FAST_MODE=false
VALID_JOBS=(fmt clippy test thumbv7em doc audit deny msrv coverage)

is_valid_job() {
    local job="$1"
    for v in "${VALID_JOBS[@]}"; do
        if [ "$v" = "$job" ]; then
            return 0
        fi
    done
    return 1
}

for arg in "$@"; do
    case "$arg" in
        --fast) FAST_MODE=true ;;
        --help|-h)
            echo "Usage: $0 [--fast] [job1 job2 ...]"
            echo ""
            echo "Jobs: ${VALID_JOBS[*]}"
            echo "  --fast   Skip slow jobs (coverage, audit, msrv)"
            exit 0
            ;;
        *)
            if is_valid_job "$arg"; then
                JOBS_TO_RUN+=("$arg")
            else
                printf "${RED}Error: unknown job '%s'${RESET}\n" "$arg" >&2
                printf "Valid jobs: %s\n" "${VALID_JOBS[*]}" >&2
                exit 1
            fi
            ;;
    esac
done

# If no jobs specified, run all
if [ ${#JOBS_TO_RUN[@]} -eq 0 ]; then
    if [ "$FAST_MODE" = true ]; then
        JOBS_TO_RUN=(fmt clippy test thumbv7em doc)
    else
        JOBS_TO_RUN=(fmt clippy test thumbv7em doc audit deny msrv coverage)
    fi
fi

should_run() {
    local job="$1"
    for j in "${JOBS_TO_RUN[@]}"; do
        if [ "$j" = "$job" ]; then
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# Job runner
# ---------------------------------------------------------------------------

run_job() {
    local name="$1"
    shift
    local description="$1"
    shift

    printf "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
    printf "${BOLD}▶ [%s] %s${RESET}\n" "$name" "$description"
    printf "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"

    local start_time
    start_time=$(date +%s)

    if "$@"; then
        local end_time
        end_time=$(date +%s)
        local elapsed=$((end_time - start_time))
        TOTAL_TIME=$((TOTAL_TIME + elapsed))
        PASS_COUNT=$((PASS_COUNT + 1))
        RESULTS+=("${GREEN}✓${RESET} ${name} (${elapsed}s)")
        printf "\n${GREEN}✓ [%s] PASSED${RESET} (%ds)\n" "$name" "$elapsed"
    else
        local end_time
        end_time=$(date +%s)
        local elapsed=$((end_time - start_time))
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
    # Check if target is installed
    if ! rustup target list --installed | grep -q thumbv7em-none-eabihf; then
        echo "Installing thumbv7em-none-eabihf target..."
        rustup target add thumbv7em-none-eabihf
    fi

    # Core crates
    cargo check --target thumbv7em-none-eabihf \
        -p vs-types \
        -p vs-crypto \
        -p vs-can-monitor \
        -p vs-eth-monitor \
        -p vs-netfw \
        -p vs-policy-engine \
        -p vs-event-logger \
        -p vs-runtime

    # Auto crates
    cargo check --target thumbv7em-none-eabihf \
        -p vs-types-auto \
        -p vs-signal-ids

    # Embedded crates
    cargo check --target thumbv7em-none-eabihf \
        -p vs-types-embedded \
        -p vs-mqtt-monitor \
        -p vs-coap-monitor \
        -p vs-runtime-embedded

    # Industrial crates
    cargo check --target thumbv7em-none-eabihf \
        -p vs-types-ind \
        -p vs-modbus-monitor-ind \
        -p vs-runtime-ind
}

job_doc() {
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items
}

job_audit() {
    if ! command -v cargo-audit &>/dev/null; then
        echo "Installing cargo-audit..."
        cargo install cargo-audit --locked
    fi
    # Use a separate DB path to avoid conflicts with cargo-deny's advisory DB cache
    cargo audit --db "${CARGO_HOME:-$HOME/.cargo}/advisory-db-audit"
}

job_deny() {
    if ! command -v cargo-deny &>/dev/null; then
        echo "Installing cargo-deny..."
        cargo install cargo-deny --locked
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

    cargo deny check
}

job_msrv() {
    local msrv="1.82.0"

    # Check if the MSRV toolchain is installed
    if ! rustup toolchain list | grep -q "$msrv"; then
        echo "Installing Rust $msrv toolchain..."
        rustup toolchain install "$msrv" --profile minimal
    fi

    # Run cargo check with the MSRV toolchain
    cargo +"$msrv" check --workspace
}

job_coverage() {
    if ! command -v cargo-llvm-cov &>/dev/null; then
        echo "Installing cargo-llvm-cov..."
        cargo install cargo-llvm-cov --version 0.6.16 --locked
    fi

    # Ensure llvm-tools component is available
    if ! rustup component add llvm-tools-preview; then
        echo "Warning: failed to add llvm-tools-preview component" >&2
    fi

    local cov_output="target/lcov.info"
    cargo llvm-cov --workspace --lcov --output-path "$cov_output"
    echo ""
    echo "Coverage report written to $cov_output"

    # Print summary if coverage file exists
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

printf "${BOLD}${CYAN}"
printf "╔══════════════════════════════════════════════════════════╗\n"
printf "║        Craton Shield Local CI Runner                    ║\n"
printf "║        Replicates .github/workflows/ci.yml              ║\n"
printf "╚══════════════════════════════════════════════════════════╝\n"
printf "${RESET}"
printf "Platform: %s %s\n" "$(uname -s)" "$(uname -m)"
printf "Rust:     %s\n" "$(rustc --version)"
printf "Jobs:     %s\n" "${JOBS_TO_RUN[*]}"

# Run each job
if should_run fmt;       then run_job "fmt"       "Check formatting (cargo fmt)"     job_fmt;       fi
if should_run clippy;    then run_job "clippy"    "Lint (clippy, deny warnings)"     job_clippy;    fi
if should_run test;      then run_job "test"      "Run all tests"                    job_test;      fi
if should_run thumbv7em; then run_job "thumbv7em" "Check no_std (Cortex-M target)"   job_thumbv7em; fi
if should_run doc;       then run_job "doc"       "Build docs (warnings = errors)"   job_doc;       fi
if should_run audit;     then run_job "audit"     "Security audit (cargo audit)"     job_audit;     fi
if should_run deny;      then run_job "deny"      "Dependency policy (cargo deny)"   job_deny;      fi
if should_run msrv;      then run_job "msrv"      "Check MSRV (Rust 1.82.0)"        job_msrv;      fi
if should_run coverage;  then run_job "coverage"  "Code coverage (cargo-llvm-cov)"   job_coverage;  fi

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
