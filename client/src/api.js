const API_BASE = "http://localhost:4000";

// Stage 1: 액세스 토큰은 새로고침 시 사라지는 메모리 저장 방식
let accessToken = null;

// 현재 메모리에 토큰이 있는지 확인(메모리 저장 상태만 가능)
export function hasToken() {
  return !!accessToken;
}

// 메모리에 보관된 토큰을 지워서 인증 상태를 끔
export function clearToken() {
  accessToken = null;
}

// Authorization 헤더를 구성, 토큰이 없으면 빈 객체 반환
function getAuthHeaders() {
  return accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
}

// 공통 Fetch 래퍼: JSON 요청/응답 및 에러 처리
async function request(path, { method = "GET", body } = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...getAuthHeaders(),
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.message || `HTTP ${res.status}`);
  return data;
}

export async function login(username, password) {
  const data = await request("/login", {
    method: "POST",
    body: { username, password },
  });
  // 로그인 성공 시 받은 액세스 토큰을 메모리에 저장
  accessToken = data.accessToken;
  return data;
}

export async function me() {
  // 현재 토큰으로 /me를 호출하면 인증된 사용자 정보를 가져옴
  return request("/me");
}

export async function logout() {
  // 서버 로그아웃 호출 후 클라이언트 토큰을 제거해 인증 상태 초기화
  await request("/logout", { method: "POST" });
  clearToken();
}
