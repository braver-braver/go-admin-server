#!/usr/bin/env bash
# Runs the frontend's Playwright suites against this server, deployed like
# production: the frontend build and the API behind one origin, no mocks.
#
#   FRONTEND=../react-admin-starter TEST_DATABASE_URL=postgres://... scripts/frontend-e2e.sh
#
# The suites assume a fresh mock per test, so every test gets a freshly seeded
# database. Set PW_CHROMIUM to use a preinstalled Chromium.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${FRONTEND:?path to a react-admin-starter checkout}"
: "${TEST_DATABASE_URL:?postgres URL of a role that can create databases}"
FRONTEND=$(cd "$FRONTEND" && pwd)
WORK=$(mktemp -d)
go build -o "$WORK/server" ./cmd/server
go build -o "$WORK/gateway" ./tools/gateway
(cd "$FRONTEND" && VITE_ENABLE_MOCKS=false pnpm -s build >/dev/null)
cat > "$FRONTEND/playwright.backend.config.ts" <<'TS'
import { defineConfig } from 'playwright/test'
export default defineConfig({
  testDir: './e2e',
  testMatch: ['app.e2e.ts', 'system.e2e.ts', 'tickets.e2e.ts'],
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:5190',
    browserName: 'chromium',
    locale: 'zh-CN',
    timezoneId: 'Asia/Shanghai',
    colorScheme: 'light',
    contextOptions: { reducedMotion: 'reduce' },
    viewport: { width: 1440, height: 900 },
    launchOptions: process.env.PW_CHROMIUM ? { executablePath: process.env.PW_CHROMIUM } : {},
  },
})
TS
DB="${TEST_DATABASE_URL%/*}/goadmin_e2e?${TEST_DATABASE_URL#*\?}"
[[ "$TEST_DATABASE_URL" == *\?* ]] || DB="${TEST_DATABASE_URL%/*}/goadmin_e2e"
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; rm -f "$FRONTEND/playwright.backend.config.ts"; }
trap cleanup EXIT
up() {
  kill "${pids[@]}" 2>/dev/null || true; pids=(); sleep 0.3
  psql "$TEST_DATABASE_URL" -qc "DROP DATABASE IF EXISTS goadmin_e2e WITH (FORCE)" -c "CREATE DATABASE goadmin_e2e"
  DATABASE_URL="$DB" "$WORK/server" seed-demo >/dev/null
  DATABASE_URL="$DB" COOKIE_SECURE=false LISTEN_ADDR=127.0.0.1:8081 LOGIN_BURST=1000 UPLOAD_DIR="$WORK/uploads" \
    "$WORK/server" >"$WORK/server.log" 2>&1 & pids+=($!)
  "$WORK/gateway" "$FRONTEND/dist" http://127.0.0.1:8081 127.0.0.1:5190 >/dev/null 2>&1 & pids+=($!)
  sleep 1
}
tests=$(cd "$FRONTEND" && npx playwright test --config playwright.backend.config.ts --list | grep -oE '[a-z.]+e2e\.ts:[0-9]+' | sed 's|^|e2e/|')
status=0
for t in $tests; do
  up
  (cd "$FRONTEND" && npx playwright test --config playwright.backend.config.ts "$t") || status=1
done
exit $status
