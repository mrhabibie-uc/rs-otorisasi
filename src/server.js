try { process.loadEnvFile(); } catch {} // baca .env jika ada (Node >= 20.12)

const path = require("path");
const express = require("express");
const { users, records } = require("./data");
const { router: authRouter, authenticate, publicUser } = require("./auth");
const { ROLES, SENSITIVITY, ROLE_PERMISSIONS, checkPermission, checkRecord } = require("./policy");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

// Catat setiap keputusan otorisasi (audit log) lalu kirim 403 jika ditolak
function decide(req, res, action, target, decision) {
  const verdict = decision ? `DENY (${decision.policy})` : "ALLOW";
  console.log(`[AUTHZ] ${req.user.username} (${req.user.role}) ${action} ${target} -> ${verdict}`);
  if (decision) res.status(403).json({ error: "Forbidden", ...decision });
  return !decision;
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (decide(req, res, permission, req.path, checkPermission(req.user, permission))) next();
  };
}

function findRecord(req, res) {
  const record = records.find((r) => r.id === Number(req.params.id));
  if (!record) res.status(404).json({ error: "Not Found", message: `Rekam medis #${req.params.id} tidak ada` });
  return record;
}

app.get("/api", (req, res) => {
  res.json({
    name: "RS Otorisasi API",
    endpoints: {
      "POST /api/auth/login": "Login username/password -> access & refresh token (JWT)",
      "POST /api/auth/refresh": "Tukar refresh token dengan pasangan token baru",
      "POST /api/auth/logout": "Cabut refresh token",
      "GET /api/auth/google": "Login dengan Google (OAuth 2.0)",
      "GET /api/me": "Profil & atribut user dari token",
      "GET /api/records": "Daftar rekam medis yang boleh diakses (difilter policy)",
      "GET /api/records/:id": "Detail rekam medis",
      "POST /api/records": "Buat rekam medis",
      "POST /api/records/:id/notes": "Tambah catatan perawatan",
      "DELETE /api/records/:id": "Hapus rekam medis",
      "GET /api/admin/users": "Daftar user (admin)",
      "PATCH /api/admin/users/:id": "Ubah role/atribut user (admin)",
      "GET /api/policies": "Daftar izin per role",
    },
  });
});

app.use("/api/auth", authRouter);

app.get("/api/policies", (req, res) => res.json({ roles: ROLE_PERMISSIONS, sensitivity: SENSITIVITY }));

app.get("/api/me", authenticate, (req, res) => {
  res.json({ user: publicUser(req.user), token: req.claims });
});

// ---------- Rekam medis (RBAC + ABAC) ----------

app.get("/api/records", authenticate, requirePermission("record:read"), (req, res) => {
  res.json(records.filter((r) => !checkRecord(req.user, "read", r)));
});

app.get("/api/records/:id", authenticate, (req, res) => {
  const record = findRecord(req, res);
  if (record && decide(req, res, "read", `record#${record.id}`, checkRecord(req.user, "read", record))) {
    res.json(record);
  }
});

app.post("/api/records", authenticate, (req, res) => {
  const { patientId, patientName, diagnosis } = req.body || {};
  const sensitivity = Number(req.body?.sensitivity ?? 1);
  // Default ruang & departemen mengikuti atribut pembuat
  const ward = req.body?.ward || req.user.ward;
  const department = req.body?.department || req.user.department;
  if (!patientId || !patientName || !diagnosis || !SENSITIVITY[sensitivity] || !ward || !department) {
    return res.status(400).json({ error: "Bad Request",
      message: "patientId, patientName, diagnosis, ward, department wajib; sensitivity 1-3" });
  }
  const record = { patientId, patientName, ward, department, sensitivity, diagnosis, notes: [], createdBy: req.user.username };
  if (!decide(req, res, "create", `record(${ward}/${department})`, checkRecord(req.user, "create", record))) return;
  record.id = Math.max(0, ...records.map((r) => r.id)) + 1;
  records.push(record);
  res.status(201).json(record);
});

app.post("/api/records/:id/notes", authenticate, (req, res) => {
  const record = findRecord(req, res);
  if (!record) return;
  const text = String(req.body?.text || "").trim();
  if (!text) return res.status(400).json({ error: "Bad Request", message: "text wajib diisi" });
  if (!decide(req, res, "update", `record#${record.id}`, checkRecord(req.user, "update", record))) return;
  const note = { by: req.user.username, at: new Date().toISOString(), text };
  record.notes.push(note);
  res.status(201).json(record);
});

app.delete("/api/records/:id", authenticate, (req, res) => {
  const record = findRecord(req, res);
  if (!record) return;
  if (!decide(req, res, "delete", `record#${record.id}`, checkRecord(req.user, "delete", record))) return;
  records.splice(records.indexOf(record), 1);
  res.json({ message: `Rekam medis #${record.id} dihapus` });
});

// ---------- Admin (RBAC murni) ----------

app.get("/api/admin/users", authenticate, requirePermission("user:read"), (req, res) => {
  res.json(users.map(publicUser));
});

app.patch("/api/admin/users/:id", authenticate, requirePermission("user:manage"), (req, res) => {
  const user = users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: "Not Found", message: "User tidak ada" });
  const b = req.body || {};
  if (b.role !== undefined && !ROLES.includes(b.role)) return res.status(400).json({ error: "Bad Request", message: `role harus salah satu: ${ROLES.join(", ")}` });
  if (b.clearance !== undefined && ![1, 2, 3].includes(b.clearance)) return res.status(400).json({ error: "Bad Request", message: "clearance harus 1, 2, atau 3" });
  if (b.onDuty !== undefined && typeof b.onDuty !== "boolean") return res.status(400).json({ error: "Bad Request", message: "onDuty harus boolean" });
  for (const key of ["role", "department", "ward", "clearance", "onDuty", "patientId"]) {
    if (b[key] !== undefined) user[key] = b[key];
  }
  console.log(`[ADMIN] ${req.user.username} mengubah user '${user.username}': ${JSON.stringify(b)}`);
  res.json(publicUser(user));
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`RS Otorisasi berjalan di http://localhost:${PORT}`));
}

module.exports = app;
