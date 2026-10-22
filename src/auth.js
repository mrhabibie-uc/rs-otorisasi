// Autentikasi: login username/password -> JWT, refresh token, dan Google OAuth 2.0.
const crypto = require("crypto");
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { users } = require("./data");

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
if (!process.env.JWT_SECRET) console.warn("[WARN] JWT_SECRET kosong, memakai secret acak (token hilang saat restart)");
const ACCESS_TOKEN_TTL = process.env.ACCESS_TOKEN_TTL || "15m";
const REFRESH_TOKEN_TTL = process.env.REFRESH_TOKEN_TTL || "7d";
const ISSUER = "rs-otorisasi";
const AUDIENCE = "rs-otorisasi-api";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || "http://localhost:3000/api/auth/google/callback";

// Refresh token yang masih berlaku (disimpan jti-nya). Produksi: Redis/database.
const refreshTokens = new Set();

function publicUser(u) {
  const { passwordHash, ...rest } = u;
  return rest;
}

function issueTokens(user) {
  const accessToken = jwt.sign(
    { type: "access", username: user.username, role: user.role },
    JWT_SECRET,
    { subject: user.id, expiresIn: ACCESS_TOKEN_TTL, issuer: ISSUER, audience: AUDIENCE, algorithm: "HS256" }
  );
  const jti = crypto.randomUUID();
  const refreshToken = jwt.sign(
    { type: "refresh" },
    JWT_SECRET,
    { subject: user.id, jwtid: jti, expiresIn: REFRESH_TOKEN_TTL, issuer: ISSUER, audience: AUDIENCE, algorithm: "HS256" }
  );
  refreshTokens.add(jti);
  return { tokenType: "Bearer", accessToken, refreshToken, expiresIn: ACCESS_TOKEN_TTL };
}

function verify(token, type) {
  const claims = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"], issuer: ISSUER, audience: AUDIENCE });
  if (claims.type !== type) throw new jwt.JsonWebTokenError(`bukan ${type} token`);
  return claims;
}

// Middleware: validasi access token di header Authorization: Bearer <token>.
// Atribut user diambil ulang dari store, jadi perubahan role/atribut langsung berlaku.
function authenticate(req, res, next) {
  const [scheme, token] = (req.headers.authorization || "").split(" ");
  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ error: "Unauthorized", message: "Sertakan header Authorization: Bearer <access token>" });
  }
  try {
    const claims = verify(token, "access");
    const user = users.find((u) => u.id === claims.sub);
    if (!user) return res.status(401).json({ error: "Unauthorized", message: "User sudah tidak ada" });
    req.user = user;
    req.claims = claims;
    next();
  } catch (err) {
    const expired = err.name === "TokenExpiredError";
    res.status(401).json({ error: expired ? "Token expired" : "Invalid token", message: err.message });
  }
}

const router = express.Router();

router.post("/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Bad Request", message: "username dan password wajib diisi" });
  }
  const user = users.find((u) => u.username === username);
  // Pesan error sama untuk username/password salah supaya tidak membocorkan username yang valid
  if (!user || !user.passwordHash || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: "Unauthorized", message: "Username atau password salah" });
  }
  res.json({ message: "Login berhasil", user: publicUser(user), ...issueTokens(user) });
});

// Refresh token rotation: token lama dicabut, pasangan token baru diterbitkan
router.post("/refresh", (req, res) => {
  const { refreshToken } = req.body || {};
  try {
    const claims = verify(refreshToken || "", "refresh");
    if (!refreshTokens.delete(claims.jti)) throw new Error("refresh token sudah dicabut");
    const user = users.find((u) => u.id === claims.sub);
    if (!user) throw new Error("user tidak ditemukan");
    res.json({ message: "Token diperbarui", ...issueTokens(user) });
  } catch (err) {
    res.status(401).json({ error: "Invalid refresh token", message: err.message });
  }
});

router.post("/logout", (req, res) => {
  try {
    refreshTokens.delete(verify(req.body?.refreshToken || "", "refresh").jti);
  } catch {}
  res.json({ message: "Logout berhasil, refresh token dicabut" });
});

// ---------- Google OAuth 2.0 (Authorization Code flow) ----------

function readCookie(req, name) {
  const pair = (req.headers.cookie || "").split(";").map((c) => c.trim().split("=")).find(([k]) => k === name);
  return pair && pair[1];
}

// Langkah 1: redirect user ke Authorization Server Google, dengan state anti-CSRF
router.get("/google", (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    return res.status(503).json({ error: "Google OAuth belum dikonfigurasi", message: "Isi GOOGLE_CLIENT_ID dan GOOGLE_CLIENT_SECRET di .env" });
  }
  const state = crypto.randomBytes(16).toString("hex");
  res.cookie("oauth_state", state, { httpOnly: true, sameSite: "lax", maxAge: 10 * 60 * 1000 });
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.search = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: "code",
    scope: "openid email profile",
    state,
    prompt: "select_account",
  });
  res.redirect(url.toString());
});

// Langkah 2: Google redirect balik membawa authorization code
router.get("/google/callback", async (req, res) => {
  const { code, state, error } = req.query;
  res.clearCookie("oauth_state");
  if (error) return res.redirect(`/#error=${encodeURIComponent(error)}`);
  if (!state || state !== readCookie(req, "oauth_state")) {
    return res.status(400).json({ error: "Bad Request", message: "state OAuth tidak cocok (kemungkinan CSRF)" });
  }
  try {
    // Langkah 3: tukar authorization code dengan access token Google (Token Endpoint)
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: "authorization_code",
      }),
    });
    const googleToken = await tokenRes.json();
    if (!tokenRes.ok) throw new Error(googleToken.error_description || googleToken.error);

    // Langkah 4: pakai access token Google untuk mengakses Resource Server Google (userinfo)
    const infoRes = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: { Authorization: `Bearer ${googleToken.access_token}` },
    });
    const profile = await infoRes.json();
    if (!infoRes.ok || !profile.email_verified) throw new Error("profil Google tidak valid / email belum terverifikasi");

    // Langkah 5: hubungkan ke akun lokal (berdasarkan email), atau buat akun baru dengan role paling rendah
    let user = users.find((u) => u.googleId === profile.sub || u.email === profile.email);
    if (!user) {
      user = { id: String(users.length + 1), username: profile.email, name: profile.name, email: profile.email,
        role: "pasien", patientId: null, passwordHash: null };
      users.push(user);
    }
    user.googleId = profile.sub;
    user.picture = profile.picture;
    console.log(`[AUTH] Google login: ${profile.email} -> user '${user.username}' (role ${user.role})`);

    // Langkah 6: terbitkan JWT aplikasi sendiri, dikirim lewat fragment URL (tidak masuk log server)
    const t = issueTokens(user);
    res.redirect(`/#accessToken=${t.accessToken}&refreshToken=${t.refreshToken}&via=google`);
  } catch (err) {
    console.error("[AUTH] Google OAuth gagal:", err.message);
    res.redirect(`/#error=${encodeURIComponent(err.message)}`);
  }
});

module.exports = { router, authenticate, publicUser };
