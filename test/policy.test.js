// Jalankan: npm test
const test = require("node:test");
const assert = require("node:assert");
const app = require("../src/server");
const { users, records } = require("../src/data");
const { checkRecord, checkPermission } = require("../src/policy");

const u = (name) => users.find((x) => x.username === name);
const rec = (id) => records.find((r) => r.id === id);
const policyOf = (user, action, id) => checkRecord(u(user), action, rec(id))?.policy ?? "ALLOW";

test("matriks keputusan policy", () => {
  const cases = [
    // [user, action, record, hasil]
    ["admin", "delete", 4, "ALLOW"], // R1
    ["dewi", "read", 1, "ALLOW"], ["dewi", "read", 3, "A1"], ["dewi", "delete", 1, "R5"],
    ["dr.andi", "read", 3, "A2"], ["ns.citra", "read", 4, "A3"],
    ["dr.andi", "read", 2, "ALLOW"], ["ns.budi", "read", 2, "G1"],
    ["ns.budi", "update", 1, "ALLOW"], ["ns.citra", "update", 3, "G2"],
    ["dr.andi", "delete", 5, "G3"], ["ns.budi", "delete", 1, "R5"],
  ];
  for (const [user, action, id, expected] of cases) {
    assert.strictEqual(policyOf(user, action, id), expected, `${user} ${action} #${id}`);
  }
  assert.strictEqual(checkPermission(u("dr.andi"), "user:read").policy, "R5");
  assert.strictEqual(checkPermission(u("admin"), "user:read"), null);
});

test("alur HTTP: login JWT, akses berbasis policy, refresh", async (t) => {
  const server = app.listen(0);
  t.after(() => server.close());
  const base = `http://localhost:${server.address().port}`;
  const call = async (method, path, token, body) => {
    const res = await fetch(base + path, { method, body: body && JSON.stringify(body),
      headers: { "Content-Type": "application/json", ...(token && { Authorization: `Bearer ${token}` }) } });
    return { status: res.status, data: await res.json() };
  };

  assert.strictEqual((await call("GET", "/api/records")).status, 401);
  assert.strictEqual((await call("GET", "/api/records", "bukan.token.valid")).status, 401);
  assert.strictEqual((await call("POST", "/api/auth/login", null, { username: "eko", password: "salah" })).status, 401);

  const login = await call("POST", "/api/auth/login", null, { username: "ns.budi", password: "perawat123" });
  assert.strictEqual(login.status, 200);
  const list = await call("GET", "/api/records", login.data.accessToken);
  assert.deepStrictEqual(list.data.map((r) => r.id), [1, 5]); // Melati, tanpa data Rahasia
  assert.strictEqual((await call("GET", "/api/records/2", login.data.accessToken)).data.policy, "G1");
  assert.strictEqual((await call("GET", "/api/admin/users", login.data.accessToken)).status, 403);

  const refreshed = await call("POST", "/api/auth/refresh", null, { refreshToken: login.data.refreshToken });
  assert.strictEqual(refreshed.status, 200);
  // rotation: refresh token lama tidak bisa dipakai lagi
  assert.strictEqual((await call("POST", "/api/auth/refresh", null, { refreshToken: login.data.refreshToken })).status, 401);
});
