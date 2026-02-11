const API_BASE = "http://localhost:4000";

// Stage 3: Access Token은 메모리, Refresh Token은 HttpOnly Cookie(서버가 Set-Cookie)
let accessToken = null;
const tokenListeners = new Set();

function notifyTokenChange(payload) {
  tokenListeners.forEach((listener) => {
    try {
      listener(payload);
    } catch {
      // ignore listener errors to keep other subscribers running
    }
  });
}

export function hasToken() {
  return !!accessToken;
}

export function clearToken() {
  accessToken = null;
  notifyTokenChange({ accessToken: null, expiresInSec: null, cause: "clear" });
}

function authHeaders() {
  return accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
}

async function parseJsonSafe(res) {
  try {
    return await res.json();
  } catch {
    return {};
  }
}

// ✅ 공통 요청 함수 (쿠키 포함)
async function request(path, { method = "GET", body, withAuth = true } = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    credentials: "include", // ✅ Stage3 필수(Refresh 쿠키 저장/전송)
    headers: {
      "Content-Type": "application/json",
      ...(withAuth ? authHeaders() : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const data = await parseJsonSafe(res);
  if (!res.ok) {
    const err = new Error(data?.message || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

// ✅ Refresh로 Access 재발급
export async function refreshAccess() {
  const data = await request("/auth/refresh", {
    method: "POST",
    withAuth: false,
  });
  accessToken = data.accessToken;
  notifyTokenChange({
    accessToken: data.accessToken,
    expiresInSec: data.expiresInSec,
    cause: "refresh",
  });
  return data;
}

// ✅ 로그인: Access(JSON) + Refresh(HttpOnly Cookie)
export async function login(username, password) {
  const data = await request("/login", {
    method: "POST",
    body: { username, password },
    withAuth: false,
  });

  accessToken = data.accessToken;
  notifyTokenChange({
    accessToken: data.accessToken,
    expiresInSec: data.expiresInSec,
    cause: "login",
  });
  return data;
}

// ✅ 보호 API 호출: 401이면 refresh 시도 후 1회 재시도
export async function me() {
  try {
    return await request("/me");
  } catch (e) {
    if (e.status !== 401) throw e;

    // access 만료/없음 → refresh 시도
    await refreshAccess();

    // refresh 성공 → 원래 요청 재시도(딱 1번)
    return await request("/me");
  }
}

export async function logout() {
  // 서버가 refresh 쿠키 삭제/폐기
  await request("/logout", { method: "POST", withAuth: false });
  clearToken();
}

export function subscribeTokenChange(listener) {
  tokenListeners.add(listener);
  return () => tokenListeners.delete(listener);
}
