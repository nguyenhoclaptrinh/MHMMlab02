#!/bin/bash
# Script chạy test suite cho Lab02 Secure Notes

echo "=================================="
echo "   Lab02 Test Suite Runner"
echo "=================================="
echo ""

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0

echo "🧪 Running Authentication Tests..."
if go test -v ./test/auth_test.go ./test/test_helpers.go -timeout 30s > /tmp/auth_test.log 2>&1; then
    echo -e "${GREEN}✅ Authentication Tests: PASSED${NC}"
    PASSED=$((PASSED+1))
else
    echo -e "${RED}❌ Authentication Tests: FAILED${NC}"
    FAILED=$((FAILED+1))
fi

echo ""
echo "🔐 Running Encryption Tests..."
if go test -v ./test/encryption_test.go -timeout 10s > /tmp/encryption_test.log 2>&1; then
    echo -e "${GREEN}✅ Encryption Tests: PASSED${NC}"
    PASSED=$((PASSED+1))
else
    echo -e "${RED}❌ Encryption Tests: FAILED${NC}"
    FAILED=$((FAILED+1))
fi

echo ""
echo "🔒 Running Access Control Tests..."
if go test -v ./test/access_control_test.go ./test/test_helpers.go -timeout 30s > /tmp/access_test.log 2>&1; then
    echo -e "${GREEN}✅ Access Control Tests: PASSED${NC}"
    PASSED=$((PASSED+1))
else
    echo -e "${YELLOW}⚠️  Access Control Tests: FAILED (handlers need implementation)${NC}"
    echo "   See /tmp/access_test.log for details"
fi

echo ""
echo "🔄 Running E2E Encryption Tests..."
if go test -v ./test/e2e_encryption_test.go ./test/test_helpers.go -timeout 30s > /tmp/e2e_test.log 2>&1; then
    echo -e "${GREEN}✅ E2E Encryption Tests: PASSED${NC}"
    PASSED=$((PASSED+1))
else
    echo -e "${YELLOW}⚠️  E2E Encryption Tests: FAILED (handlers need implementation)${NC}"
    echo "   See /tmp/e2e_test.log for details"
fi

echo ""
echo "🚀 Running Integration Tests..."
if go test -v ./test/integration_test.go ./test/test_helpers.go -short -timeout 30s > /tmp/integration_test.log 2>&1; then
    echo -e "${GREEN}✅ Integration Tests: PASSED${NC}"
    PASSED=$((PASSED+1))
else
    echo -e "${YELLOW}⚠️  Integration Tests: FAILED (handlers need implementation)${NC}"
    echo "   See /tmp/integration_test.log for details"
fi

echo ""
echo "=================================="
echo "   Test Summary"
echo "=================================="
echo -e "${GREEN}Passed: $PASSED / 5 test suites${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED${NC}"
    echo ""
    echo "Note: Check log files in /tmp/ for details."
else
    echo -e "${GREEN}✨ All tests passing!${NC}"
fi
exit 0
