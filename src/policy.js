// Policy Decision Point: semua aturan akses ada di file ini.
// Keputusan: null = izinkan, { policy, reason } = tolak.

const ROLES = ["admin", "dokter", "perawat", "pasien"];
const SENSITIVITY = { 1: "Umum", 2: "Sensitif", 3: "Rahasia" };

// RBAC: izin per role (R1-R4)
const ROLE_PERMISSIONS = {
  admin: ["user:read", "user:manage", "record:read", "record:create", "record:update", "record:delete"],
  dokter: ["record:read", "record:create", "record:update", "record:delete"],
  perawat: ["record:read", "record:update"],
  pasien: ["record:read"],
};

const deny = (policy, reason) => ({ policy, reason });

function hasPermission(user, permission) {
  return (ROLE_PERMISSIONS[user.role] || []).includes(permission);
}

// RBAC murni, dipakai endpoint yang tidak menyentuh resource tertentu (mis. /api/admin/*)
function checkPermission(user, permission) {
  if (hasPermission(user, permission)) return null;
  return deny("R5", `Role '${user.role}' tidak memiliki izin '${permission}'`);
}

// RBAC + ABAC untuk rekam medis. action: read | create | update | delete
function checkRecord(user, action, record) {
  const rbac = checkPermission(user, `record:${action}`);
  if (rbac) return rbac;

  // R1: admin mengelola seluruh data
  if (user.role === "admin") return null;

  // A1: pasien hanya rekam medis miliknya sendiri
  if (user.role === "pasien") {
    return record.patientId === user.patientId
      ? null
      : deny("A1", `Rekam medis milik pasien ${record.patientId}, bukan milik Anda (${user.patientId})`);
  }

  // A2: tenaga medis hanya rekam medis pasien di ruang rawatnya
  if (record.ward !== user.ward) {
    return deny("A2", `Pasien dirawat di ruang ${record.ward}, Anda bertugas di ruang ${user.ward}`);
  }

  // A3: clearance pengguna harus >= sensitivitas data
  if (user.clearance < record.sensitivity) {
    return deny("A3", `Clearance Anda ${user.clearance} lebih rendah dari sensitivitas data ` +
      `${record.sensitivity} (${SENSITIVITY[record.sensitivity]})`);
  }

  // G1: data Rahasia hanya untuk role dokter (perawat ditolak walau clearance cukup)
  if (record.sensitivity === 3 && user.role !== "dokter") {
    return deny("G1", `Data Rahasia hanya untuk dokter, role Anda '${user.role}'`);
  }

  // G2: menambah catatan perawatan butuh status sedang bertugas
  if (action === "update" && !user.onDuty) {
    return deny("G2", "Anda tidak sedang bertugas (onDuty = false)");
  }

  // G3: membuat/menghapus rekam medis hanya dokter dari departemen yang sama
  if ((action === "create" || action === "delete") && record.department !== user.department) {
    return deny("G3", `Rekam medis milik departemen ${record.department}, ` +
      `Anda dari departemen ${user.department}`);
  }

  return null;
}

module.exports = { ROLES, SENSITIVITY, ROLE_PERMISSIONS, checkPermission, checkRecord };
