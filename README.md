# mini-auth-lab

인증(Auth)을 **단계별로 구현/보완**하면서 동작과 보안 트레이드오프를 직접 확인하는 실습용 레포입니다.

- `client/` – React 19 + Vite 5 기반 SPA
- `server/` – Express 5 기반 인증 API

## 현재 단계

- **Stage 1: Access Token only**
  - 로그인 성공 시 서버가 Access Token(JWT)을 JSON으로 반환
  - 클라이언트는 토큰을 **메모리**에 저장하고 `Authorization: Bearer ...`로 보호 API를 호출

## 시작하기

1. 루트에서 의존성 설치:

````bash
npm install --prefix client
npm install --prefix server
각각 다른 터미널에서 실행:

bash
코드 복사
npm run dev --prefix server
npm run dev --prefix client
접속

Client: http://localhost:5173

Server: http://localhost:4000

테스트 시나리오 (Stage 1)
로그인 전 Call /me → 401

demo / demo로 로그인 → Call /me → 200

Access 만료 후 Call /me → 401 (Stage 1은 refresh가 없으므로 재로그인 필요)

저장소 구조
client/ – React/Vite 프론트엔드

server/ – Express + jsonwebtoken 백엔드

라이선스
MIT License. 자세한 내용은 LICENSE 파일을 참고하세요.

sql
코드 복사

저장 후 커밋/푸시는 이렇게:

```bash
git add README.md
git commit -m "docs: update readme for stage 1"
git push
````
