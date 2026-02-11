import { useCallback, useEffect, useMemo, useState } from "react";
import { hasToken, login, logout, me, subscribeTokenChange } from "./api";
import "./App.css";

export default function App() {
  const [username, setUsername] = useState("demo");
  const [password, setPassword] = useState("demo");
  const [logs, setLogs] = useState([]);
  const [tokenState, setTokenState] = useState(hasToken());
  const [refreshCount, setRefreshCount] = useState(0);
  const [lastRefresh, setLastRefresh] = useState(null);

  const pushLog = useCallback((msg) => {
    const line = `${new Date().toLocaleTimeString()}  ${msg}`;
    setLogs((prev) => [line, ...prev]);
  }, []);

  const [expiresAt, setExpiresAt] = useState(null); // epoch ms
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  const remainingSec = useMemo(() => {
    if (!expiresAt) return null;
    return Math.max(0, Math.floor((expiresAt - now) / 1000));
  }, [expiresAt, now]);

  const tokenLabel = useMemo(() => {
    if (!tokenState) return "NO";
    if (!expiresAt) return "YES (in memory)";
    if (remainingSec <= 0) return "YES (expired)";
    return `YES (expires in ${remainingSec}s)`;
  }, [tokenState, expiresAt, remainingSec]);

  const refreshLabel = useMemo(() => {
    if (!refreshCount) return "자동 갱신 없음";
    const formattedTime = lastRefresh
      ? new Date(lastRefresh).toLocaleTimeString()
      : "알 수 없음";
    return `자동 갱신 ${refreshCount}회 · 마지막 ${formattedTime}`;
  }, [refreshCount, lastRefresh]);

  useEffect(() => {
    const unsubscribe = subscribeTokenChange((info) => {
      if (!info) return;
      setTokenState(Boolean(info.accessToken));
      if (typeof info.expiresInSec === "number") {
        setExpiresAt(Date.now() + info.expiresInSec * 1000);
      } else {
        setExpiresAt(null);
      }

      if (info.cause === "refresh") {
        setRefreshCount((prev) => prev + 1);
        setLastRefresh(Date.now());
        pushLog(
          `Access 자동 갱신: ${info.expiresInSec ?? "unknown"}초 · 새 토큰 사용`,
        );
      } else if (info.cause === "login") {
        setRefreshCount(0);
        setLastRefresh(null);
      } else if (info.cause === "clear") {
        setRefreshCount(0);
        setLastRefresh(null);
      }
    });
    return unsubscribe;
  }, [pushLog]);

  return (
    <div className="app-shell">
      <main className="app-layout">
        <header className="app-heading">
          <p className="eyebrow">3단계 · Refresh 쿠키로 Access 자동 재발급</p>
          <h1>mini-auth-lab</h1>
          <p className="subtitle">
            서버 http://localhost:4000 · 클라이언트 http://localhost:5173
          </p>
          <div className="status-row">
            <span className="status-label">액세스 토큰 상태(만료)</span>

            <span className="status-pill">{tokenLabel}</span>
          </div>
          <div className="status-row">
            <span className="status-label">자동 갱신 현황</span>
            <span className="status-pill">{refreshLabel}</span>
          </div>
        </header>

        <section className="app-card">
          <div className="card-header">
            <h2>사용자 정보</h2>
            <p>
              로그인 시 Refresh(HttpOnly Cookie)가 저장됩니다. Access가 만료되면
              /auth/refresh로 재발급 후 /me를 자동 재시도합니다.
            </p>

            <p className="credential-tip">테스트 계정 ID : demo · PWD : demo</p>
          </div>

          <div className="control-row">
            <label className="field">
              <span>Username</span>
              <input
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="demo"
              />
            </label>
            <label className="field">
              <span>Password</span>
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="demo"
              />
            </label>
          </div>

          <div className="actions">
            <button
              className="primary"
              onClick={async () => {
                try {
                  const response = await login(username, password);
                  setTokenState(true);
                  setExpiresAt(
                    response.expiresAt ??
                      Date.now() + response.expiresInSec * 1000,
                  );
                  pushLog(`로그인 성공 · 만료까지 ${response.expiresInSec}초`);
                } catch (error) {
                  pushLog(`로그인 실패: ${error.message}`);
                }
              }}
            >
              로그인
            </button>

            <button
              onClick={async () => {
                try {
                  const response = await me();
                  pushLog(`/me 조회 성공: ${JSON.stringify(response)}`);
                } catch (error) {
                  pushLog(`/me 조회 실패: ${error.message} (재로그인 필요)`);
                }
              }}
            >
              /me 호출
            </button>

            <button
              onClick={async () => {
                try {
                  await logout();
                  setTokenState(false);
                  setExpiresAt(null);
                  pushLog("로그아웃 성공 · 클라이언트 토큰 제거 완료");
                } catch (error) {
                  pushLog(`로그아웃 실패: ${error.message}`);
                }
              }}
            >
              로그아웃
            </button>
          </div>

          <p className="quiet">
            테스트 시나리오: (1) 로그인 → 만료 카운트다운 확인 · (2) 10초 후 /me
            · (3) refresh 토큰으로 새로 access 토큰 발급
          </p>
        </section>

        <section className="app-card log-card">
          <div className="card-header">
            <h2>활동 로그</h2>
            <p>최근 API 흐름을 타임스탬프와 함께 기록합니다.</p>
          </div>
          <div
            className="log-window"
            role="log"
            aria-live="polite"
            aria-label="Authentication activity log"
          >
            {logs.length === 0 ? (
              <p className="quiet">
                로그가 비어 있습니다. API를 호출해 보세요.
              </p>
            ) : (
              logs.map((line, index) => (
                <p key={index} className="log-line">
                  {line}
                </p>
              ))
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
