#!/bin/bash
# ddns-manager deploy healthcheck
# Usage: ./check.sh [host]  (default: localhost:9877)
set -e
HOST="${1:-localhost:9877}"
BASE="https://$HOST"
FAIL=0

check() {
  local desc="$1" url="$2" expected="$3"
  local code=$(curl -sk -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
  if [ "$code" = "$expected" ]; then
    echo "  ✅ $desc ($code)"
  else
    echo "  ❌ $desc → got $code, expected $expected"
    FAIL=1
  fi
}

echo "🔍 ddns-manager healthcheck → $BASE"
check "Ping"                "$BASE/api/ping"              "200"
check "Admin status"        "$BASE/api/admin/status"      "200"
check "Web UI"              "$BASE/"                      "200"
check "Bin download"        "$BASE/bin/node-agent-linux-amd64" "200"
check "Nodes (unauth)"      "$BASE/api/admin/nodes"       "401"

# Check that default password is blocked
TOKEN=$(echo -n "admin:Admin12345" | sha256sum | awk '{print $1}')
code=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE/api/admin/nodes" -H "Authorization: Bearer $TOKEN")
if [ "$code" = "403" ]; then
  echo "  ✅ Force password change ($code)"
else
  echo "  ❌ Force password change → got $code, expected 403"
  FAIL=1
fi

echo ""
if [ "$FAIL" = "0" ]; then
  echo "✅ All checks passed"
else
  echo "❌ Some checks failed"
  exit 1
fi
