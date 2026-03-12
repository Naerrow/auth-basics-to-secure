#!/usr/bin/env bash
set -euo pipefail

BASE_URL=${BASE_URL:-"http://localhost:4000"}
SECRET=${JWT_SECRET:-"dev-secret-change-me"}
MAX_TTL_SEC=${MAX_TTL_SEC:-30}
EXPECTED_TTL_SEC=${EXPECTED_TTL_SEC:-10}
HTTP_BODY=""
status=""
DETECTED_STAGE=""

RESULTS=()
VULNERABLE_COUNT=0
SECURE_COUNT=0
NOT_TESTABLE_COUNT=0

log() {
  echo "[`date '+%H:%M:%S'`] $*"
}

http_call() {
  curl -sS -o /tmp/attack_stage2_resp_body.txt -w "%{http_code}" "$@" > /tmp/attack_stage2_resp_code.txt
}

capture_response() {
  status="$(cat /tmp/attack_stage2_resp_code.txt)"
  HTTP_BODY="$(cat /tmp/attack_stage2_resp_body.txt)"
}

json_get() {
  local body="$1"
  local key="$2"
  node --input-type=module -e "const raw = process.argv[1] || ''; const key = process.argv[2] || ''; try { const data = JSON.parse(raw); process.stdout.write(data?.[key] ?? ''); } catch { process.stdout.write(''); }" "$body" "$key"
}

jwt_payload_exp() {
  local token="$1"
  node --input-type=module -e "const token = process.argv[1] || ''; try { const parts = token.split('.'); if (parts.length !== 3) process.exit(1); const payloadB64 = parts[1].replace(/-/g,'+').replace(/_/g,'/'); const pad = '='.repeat((4 - payloadB64.length % 4) % 4); const payload = JSON.parse(Buffer.from(payloadB64 + pad, 'base64').toString('utf8')); process.stdout.write(String(payload?.exp ?? '')); } catch { process.exit(1); }" "$token"
}

now_epoch() {
  node --input-type=module -e "console.log(Math.floor(Date.now() / 1000))"
}

add_result() {
  RESULTS+=("$1")
}

secure() {
  SECURE_COUNT=$((SECURE_COUNT + 1))
  add_result "SECURE|$1|$2"
  echo "[SECURE] $1"
}

vulnerable() {
  VULNERABLE_COUNT=$((VULNERABLE_COUNT + 1))
  add_result "VULNERABLE|$1|$2"
  echo "[VULNERABLE] $1"
}

not_testable() {
  NOT_TESTABLE_COUNT=$((NOT_TESTABLE_COUNT + 1))
  add_result "NOT_TESTABLE|$1|$2"
  echo "[NOT_TESTABLE] $1"
}

is_int() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

log "Stage2 취약점 검증 시나리오 시작 (Base: ${BASE_URL})"

log "1) 로그인 토큰 발급(전제)"
http_call -X POST "${BASE_URL}/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"demo"}'
capture_response
if [ "$status" != "200" ]; then
  not_testable "/login 전제" "HTTP ${status}"
  exit 1
fi

TOKEN=$(json_get "$HTTP_BODY" "accessToken")
if [ -z "$TOKEN" ]; then
  not_testable "accessToken 추출" "응답 본문에서 accessToken 누락"
  exit 1
fi
secure "accessToken 발급" "HTTP 200"

log "2) 대상 스테이지 확인"
http_call -H "Authorization: Bearer ${TOKEN}" "${BASE_URL}/me"
capture_response
DETECTED_STAGE="$(json_get "$HTTP_BODY" "stage")"
if [ -z "$DETECTED_STAGE" ]; then
  DETECTED_STAGE="unknown"
fi
echo "[INFO] 감지 스테이지: ${DETECTED_STAGE}"

log "3) Stage2: 액세스 토큰 유효시간이 짧고 유효 기간이 있는지"
TOKEN_EXP="$(jwt_payload_exp "$TOKEN")"
if [ -z "$TOKEN_EXP" ] || ! is_int "$TOKEN_EXP"; then
  vulnerable "액세스 토큰 유효시간 미적용" "accessToken에 exp가 없어 영구 토큰 가능성"
else
  NOW_SEC="$(now_epoch)"
  TTL_SEC=$((TOKEN_EXP - NOW_SEC))
  if [ "$TTL_SEC" -le 0 ]; then
    vulnerable "액세스 토큰 만료값 이상" "TTL이 ${TTL_SEC}s로 비정상"
  elif [ "$TTL_SEC" -gt "$MAX_TTL_SEC" ]; then
    vulnerable "액세스 토큰 TTL 과도" "현재 TTL=${TTL_SEC}s, 허용 한도 ${MAX_TTL_SEC}s 초과"
  else
    secure "액세스 토큰 유효기간 제한" "TTL=${TTL_SEC}s (<= ${MAX_TTL_SEC}s)"
    if [ "$TTL_SEC" -gt "$EXPECTED_TTL_SEC" ]; then
      secure "기본 만료정책 수치 검증 보조" "서버 TTL이 기대치보다 큼(권고=${EXPECTED_TTL_SEC}s, 실제=${TTL_SEC}s)"
    else
      secure "기본 만료정책 수치 검증" "서버 TTL=${TTL_SEC}s"
    fi
  fi
fi

log "4) Stage2: 로그아웃 후 토큰 폐기 여부"
http_call -X POST "${BASE_URL}/logout"
capture_response
if [ "$status" != "200" ]; then
  not_testable "로그아웃 동작 확인" "/logout 응답 HTTP ${status}"
else
  http_call -H "Authorization: Bearer ${TOKEN}" "${BASE_URL}/me"
  capture_response
  if [ "$status" = "401" ]; then
    secure "로그아웃 토큰 폐기" "로그아웃 후 동일 토큰이 401"
  else
    vulnerable "로그아웃 토큰 폐기 미흡" "로그아웃 후 동일 토큰 /me가 HTTP ${status}"
  fi
fi

log "5) Stage2: 만료된 액세스 토큰은 즉시 거부되는지"
TOKEN_EXP="$(jwt_payload_exp "$TOKEN")"
if [ -z "$TOKEN_EXP" ] || ! is_int "$TOKEN_EXP"; then
  not_testable "만료 토큰 차단" "토큰 exp 부재로 실제 만료 시나리오 실행 불가"
else
  NOW_SEC="$(now_epoch)"
  TTL_SEC=$((TOKEN_EXP - NOW_SEC))
  if [ "$TTL_SEC" -le 0 ]; then
    not_testable "만료 토큰 차단" "토큰 발급 시 이미 만료 상태로 판단되어 테스트 생략"
  else
    sleep $((TTL_SEC + 1))
    http_call -H "Authorization: Bearer ${TOKEN}" "${BASE_URL}/me"
    capture_response
    if [ "$status" = "401" ]; then
      secure "만료 토큰 차단" "만료 후 /me가 401"
    else
      vulnerable "만료 토큰 차단 실패" "만료 후 /me가 HTTP ${status}"
    fi
  fi
fi

log "6) Stage2: 기본 시크릿 기반 토큰 위조 허용 여부"
FORGED_TOKEN=$(node --input-type=module - <<NODE
import jwt from 'jsonwebtoken';
const token = jwt.sign(
  { sub: 'admin', typ: 'access' },
  process.env.JWT_SECRET || '${SECRET}',
  { expiresIn: 60 * 5 }
);
process.stdout.write(token);
NODE
)

http_call -H "Authorization: Bearer ${FORGED_TOKEN}" "${BASE_URL}/me"
capture_response
if [ "$status" = "401" ]; then
  secure "기본 시크릿 위조 토큰 차단" "위조 토큰이 401"
else
  vulnerable "기본 시크릿 위조 토큰 허용" "위조 토큰이 HTTP ${status}"
fi

echo
printf '%s\n' '[RESULT MATRIX]'
printf '%s\n' '결과 | 항목 | 근거'
printf '%s\n' '--------------------------------------------------------------'
for line in "${RESULTS[@]}"; do
  IFS='|' read -r result item evidence <<< "$line"
  printf '%-12s | %-50s | %s\n' "$result" "$item" "$evidence"
done

echo
TOTAL=$((VULNERABLE_COUNT + SECURE_COUNT + NOT_TESTABLE_COUNT))
echo "[SUMMARY] VULNERABLE=${VULNERABLE_COUNT}, SECURE=${SECURE_COUNT}, NOT_TESTABLE=${NOT_TESTABLE_COUNT}, TOTAL=${TOTAL}"
if [ "$VULNERABLE_COUNT" -gt 0 ]; then
  echo "[SUMMARY] Stage2에서 재현 가능한 취약점이 확인되었습니다."
  exit 2
fi

echo "[SUMMARY] Stage2 기준 취약점이 즉시 재현되지 않았습니다."
