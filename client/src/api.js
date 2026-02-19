const API_BASE = "http://localhost:4000";

// Stage 3: Access Token은 메모리, Refresh Token은 HttpOnly Cookie(서버가 Set-Cookie)
let accessToken = null;
const tokenListeners = new Set();
let refreshPromise = null;
let tokenVersion = 0;

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
  tokenVersion++;
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
  if (refreshPromise) return refreshPromise;
  refreshPromise = (async () => {
    const data = await request("/auth/refresh", {
      method: "POST",
      withAuth: false,
    });
    accessToken = data.accessToken;
    tokenVersion++;
    notifyTokenChange({
      accessToken: data.accessToken,
      expiresInSec: data.expiresInSec,
      cause: "refresh",
    });
    return data;
  })().finally(() => {
    refreshPromise = null;
  });
  return refreshPromise;
}

// ✅ 로그인: Access(JSON) + Refresh(HttpOnly Cookie)
export async function login(username, password) {
  const data = await request("/login", {
    method: "POST",
    body: { username, password },
    withAuth: false,
  });

  accessToken = data.accessToken;
  tokenVersion++;
  notifyTokenChange({
    accessToken: data.accessToken,
    expiresInSec: data.expiresInSec,
    cause: "login",
  });
  return data;
}

// ✅ 보호 API 호출: 401이면 refresh 시도 후 1회 재시도
export async function me() {
  const startVersion = tokenVersion;
  try {
    return await request("/me");
  } catch (e) {
    if (e.status !== 401) throw e;

    // 이미 다른 요청에서 refresh로 토큰이 갱신된 경우, refresh 없이 재시도
    if (tokenVersion === startVersion) {
      // access 만료/없음 → refresh 시도(동시성 제어)
      await refreshAccess();
    }

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
