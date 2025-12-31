#!/bin/bash
#
# HTTP/2 regression test runner
#
# This script runs HTTP/2 tests on PCAP files and compares output against baseline files.
#
# Test structure:
#   tests/pcap/
#     ├── test1.pcap
#     ├── test1.keys (optional - TLS keylog file)
#     ├── test1.out (baseline output, auto-generated if missing)
#     ├── test2.pcap
#     └── ...
#
# Usage:
#   ./run_http2_tests.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track overall test status
FAILED_TESTS=0
PASSED_TESTS=0
CREATED_OUTPUTS=0

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Test data directory
TEST_DIR=$(readlink -f "$SCRIPT_DIR/pcap")

TEST_EXE=http2_reader

# Build directory - look for the test executable
# Try multiple possible locations
BUILD_DIRS=(
    "$SCRIPT_DIR/build/test/test"
    "$SCRIPT_DIR/../build/test/test"
    "$SCRIPT_DIR/test"
)

# Ignore libushark-related issues
export LSAN_OPTIONS=suppressions=$(readlink -f $SCRIPT_DIR/lsan.supp):print_suppressions=0:fast_unwind_on_malloc=0

HTTP2_DIR=""
for dir in "${BUILD_DIRS[@]}"; do
    if [ -f "$dir/${TEST_EXE}" ]; then
        HTTP2_DIR="$dir"
        break
    fi
done

if [ -z "$HTTP2_DIR" ]; then
    echo -e "${RED}Error: ${TEST_EXE} executable not found${NC}"
    echo "Searched in:"
    for dir in "${BUILD_DIRS[@]}"; do
        echo "  - $dir"
    done
    echo ""
    echo "Please build the tests first:"
    echo "  cd app/src/main/jni/tests"
    echo "  mkdir -p build && cd build"
    echo "  cmake .. && make"
    exit 1
fi

echo "Using test exe: $HTTP2_DIR/${TEST_EXE}"
echo ""

# Find all .pcap files in the test directory
pcap_files=("$TEST_DIR"/*_http2*.pcap)

if [ ${#pcap_files[@]} -eq 0 ] || [ ! -f "${pcap_files[0]}" ]; then
    echo -e "${YELLOW}No HTTP/2 test PCAP files found in $TEST_DIR${NC}"
    echo "Expected files matching pattern: *_http2*.pcap"
    exit 0
fi

cd "$HTTP2_DIR"

for pcap_file in "${pcap_files[@]}"; do
    # Skip if not a file
    [ -f "$pcap_file" ] || continue

    base_name=$(basename "$pcap_file" .pcap)
    expected_out="${TEST_DIR}/${base_name}.out"

    echo "Testing: $base_name"

    # Run the command and capture output
    if ! actual_output=$(./${TEST_EXE} "$pcap_file" 2>&1); then
        echo -e "${RED}✗ FAILED: Command exited with error${NC}"
        echo "Command: $cmd"
        echo "Output:"
        echo "$actual_output"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        continue
    fi

    # Check if expected output file exists
    if [ ! -f "$expected_out" ]; then
        echo -e "${YELLOW}  WARNING: Expected output file $expected_out not found. Creating it.${NC}"
        echo "$actual_output" > "$expected_out"
        CREATED_OUTPUTS=$((CREATED_OUTPUTS + 1))

        # Verify the output is deterministic by running again
        verify_output=$(./${TEST_EXE} "$pcap_file" 2>&1)
        if [ "$actual_output" = "$verify_output" ]; then
            echo -e "${GREEN}  ✓ PASSED (verified deterministic)${NC}"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo -e "${RED}  ✗ WARNING: Output is non-deterministic!${NC}"
            echo "  First run differs from second run for $pcap_file"
        fi
        continue
    fi

    # Compare actual output with expected output
    expected_output=$(cat "$expected_out")

    if [ "$actual_output" = "$expected_output" ]; then
        echo -e "${GREEN}  ✓ PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}  ✗ FAILED${NC}"
        echo "  Output differs from expected for $pcap_file"
        echo "  Expected output file: $expected_out"
        echo ""
        echo "  Diff:"
        diff -u "$expected_out" <(echo "$actual_output") || true
        echo ""
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
done

# Print summary
echo ""
echo "========== Test Summary =========="
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
if [ $CREATED_OUTPUTS -gt 0 ]; then
    echo -e "${YELLOW}Created: $CREATED_OUTPUTS${NC}"
fi
if [ $FAILED_TESTS -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"
fi
echo "=================================="

# Exit with error if any tests failed
if [ $FAILED_TESTS -gt 0 ] || [ $CREATED_OUTPUTS -gt 0 ]; then
    exit 1
fi

exit 0
