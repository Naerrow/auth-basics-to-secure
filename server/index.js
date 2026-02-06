import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());

const PORT = 4000;
const CLIENT_ORIGIN = "http://localhost:5173";
const STAGE = Number(process.env.STAGE || 1);
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const ACCESS_TTL_SEC = 60 * 5;

app.use(
  cors({
    origin: CLIENT_ORIGIN,
    credentials: false,
  })
);

function signAccessToken(userId) {
  return jwt.sign({ sub: userId, typ: "access" }, JWT_SECRET, { expiresIn: ACCESS_TTL_SEC });
}

function requireAccess(req, res, next) {
  const auth = req.header("Authorization") || "";
  const [type, token] = auth.split(" ");
  if (type !== "Bearer" || !token) return res.status(401).json({ message: "Missing Authorization Bearer token" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.typ !== "access") throw new Error("Not an access token");
    req.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired access token" });
  }
}

app.post("/login", (req, res) => {
  if (STAGE !== 1) return res.status(400).json({ message: "This endpoint is Stage1-only in current setup." });

  const { username, password } = req.body;
  if (username !== "demo" || password !== "demo") return res.status(401).json({ message: "Bad credentials" });

  const accessToken = signAccessToken("user-1");
  res.json({ accessToken, tokenType: "Bearer", expiresInSec: ACCESS_TTL_SEC });
});

app.get("/me", requireAccess, (req, res) => {
  res.json({ userId: req.userId, message: "You are authenticated with Access Token only (Stage 1)." });
});

app.post("/logout", (req, res) => {
  res.json({ message: "Stage1 logout: client should delete token locally." });
});

app.listen(PORT, () => console.log(`Server running: http://localhost:${PORT} (STAGE=${STAGE})`));
