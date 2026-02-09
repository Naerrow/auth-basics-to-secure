import { useEffect, useMemo, useState } from "react";
import { hasToken, login, logout, me } from "./api";
import "./App.css";

export default function App() {
  const [username, setUsername] = useState("demo");
  const [password, setPassword] = useState("demo");
  const [logs, setLogs] = useState([]);
  const [tokenState, setTokenState] = useState(hasToken());

  const pushLog = (msg) => {
    const line = `${new Date().toLocaleTimeString()}  ${msg}`;
    setLogs((prev) => [line, ...prev]);
  };

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

  return (
    <div className="app-shell">
      <main className="app-layout">
        <header className="app-heading">
          <p className="eyebrow">2단계 · 액세스 토큰 만료 재현(10초)</p>
          <h1>mini-auth-lab</h1>
          <p className="subtitle">
            서버 http://localhost:4000 · 클라이언트 http://localhost:5173
          </p>
          <div className="status-row">
            <span className="status-label">액세스 토큰 상태(만료)</span>

            <span className="status-pill">{tokenLabel}</span>
          </div>
        </header>

        <section className="app-card">
          <div className="card-header">
            <h2>사용자 정보</h2>
            <p>
              로그인 후 토큰 만료(10초) → /me 401 → 재로그인 필요 흐름을
              확인하세요.
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
                  pushLog(
                    `/me 조회 실패: ${error.message} (Stage 2: 재로그인 필요)`,
                  );
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
            → 401 · (3) 다시 로그인 → /me → 200
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
